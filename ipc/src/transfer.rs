
use core::intrinsics::likely;

use common::{message_info::seL4_MessageInfo_t, fault::*, sel4_config::{seL4_MsgMaxExtraCaps, MessageID_Syscall, MessageID_Exception}, utils::convert_to_mut_type_ref, structures::exception_t};
use cspace::interface::{cte_t, CapTag, cte_insert};
use task_manager::{tcb_t, msgInfoRegister, badgeRegister, n_syscallMessage, n_exceptionMessage, FaultIP, ThreadState, set_thread_state, possible_switch_to};
use vspace::pptr_t;

use crate::endpoint_t;

pub fn do_fault_transfer(badge: usize, sender: &tcb_t, receiver: &mut tcb_t) {
    let sent = match sender.tcbFault.get_fault_type() {
        common::fault::FaultType::CapFault => {
            receiver.set_mr(seL4_CapFault_IP, sender.get_register(FaultIP));
            receiver.set_mr(seL4_CapFault_Addr, sender.tcbFault.cap_fault_get_address());
            receiver.set_mr(seL4_CapFault_InRecvPhase, sender.tcbFault.cap_fault_get_in_receive_phase());
            receiver.set_lookup_fault_mrs(seL4_CapFault_LookupFailureType, &sender.tcbLookupFailure)
        },
        common::fault::FaultType::UnknownSyscall => {
            sender.copy_syscall_fault_mrs(receiver);
            receiver.set_mr(n_syscallMessage, sender.tcbFault.unknown_syscall_get_syscall_number())
        },
        common::fault::FaultType::UserException => {
            sender.copy_exeception_fault_mrs(receiver);
            receiver.set_mr(n_exceptionMessage, sender.tcbFault.user_exeception_get_number());
            receiver.set_mr(n_exceptionMessage + 1, sender.tcbFault.user_exeception_get_code())
        },
        common::fault::FaultType::VMFault => {
            receiver.set_mr(seL4_VMFault_IP, sender.get_register(FaultIP));
            receiver.set_mr(seL4_VMFault_Addr, sender.tcbFault.vm_fault_get_address());
            receiver.set_mr(seL4_VMFault_PrefetchFault, sender.tcbFault.vm_fault_get_instruction_fault());
            receiver.set_mr(seL4_VMFault_FSR, sender.tcbFault.vm_fault_get_fsr())
        },
        _ => {
            panic!("invalid fault")
        }
    };
    let msg_info = seL4_MessageInfo_t::new(sender.tcbFault.get_type(), 0, 0, sent);
    receiver.set_register(msgInfoRegister, msg_info.to_word());
    receiver.set_register(badgeRegister, badge);
}

pub fn do_caps_transfer(info: &mut seL4_MessageInfo_t, endpoint: Option<&endpoint_t>, receiver: &mut tcb_t, current_extra_caps: &[pptr_t; seL4_MsgMaxExtraCaps]) {
    info.set_extra_caps(0);
    info.set_caps_unwrapped(0);
    let ipc_buffer = receiver.lookup_mut_ipc_buffer(true);
    if current_extra_caps[0] as usize == 0 || ipc_buffer.is_none() {
        return;
    }
    let buffer = ipc_buffer.unwrap();
    let mut dest_slot = receiver.get_receive_slot();
    let mut i = 0;
    while i < seL4_MsgMaxExtraCaps && current_extra_caps[i] as usize != 0 {
        let slot = convert_to_mut_type_ref::<cte_t>(current_extra_caps[i]);
        let cap = &slot.cap.clone();
        if cap.get_cap_type() == CapTag::CapEndpointCap && endpoint.is_some() && cap.get_ep_ptr() == endpoint.unwrap().get_ptr() {
            buffer.caps_or_badges[i] = cap.get_ep_badge();
            info.set_caps_unwrapped(info.get_caps_unwrapped() | (1 << i));
        } else {
            if dest_slot.is_none() {
                break;
            } else {
                let dest = dest_slot.take();
                let dc_ret = slot.derive_cap(cap);
                if dc_ret.status != exception_t::EXCEPTION_NONE || dc_ret.cap.get_cap_type() == CapTag::CapNullCap {
                    break;
                }
                cte_insert(&dc_ret.cap, slot, dest.unwrap());
            }
        }
        i += 1;
    }
    info.set_extra_caps(i);
}


fn do_normal_transfer(sender: &tcb_t,endpoint: Option<&endpoint_t>, badge: usize, can_grant: bool, receiver: &mut tcb_t) {
    let mut tag = seL4_MessageInfo_t::from_word_security(sender.get_register(msgInfoRegister));
    let mut current_extra_caps = [0; seL4_MsgMaxExtraCaps];
    if can_grant {
        let _ = sender.lookup_extra_caps(&mut current_extra_caps);
    }
    let msg_transferred = sender.copy_mrs(receiver, tag.get_length());
    do_caps_transfer(&mut tag, endpoint, receiver, &current_extra_caps);
    tag.set_length(msg_transferred);
    receiver.set_register(msgInfoRegister, tag.to_word());
    receiver.set_register(badgeRegister, badge);
}


pub fn do_ipc_transfer(sender: &tcb_t, endpoint: Option<&endpoint_t>, badge: usize, grant: bool, receiver: &mut tcb_t) {
    if likely(sender.tcbFault.get_fault_type() == FaultType::NullFault) {
        do_normal_transfer(sender, endpoint, badge, grant, receiver)
    } else {
        do_fault_transfer(badge, sender, receiver)
    }
}

#[no_mangle]
pub fn doIPCTransfer(
    sender: *mut tcb_t,
    endpoint: *mut endpoint_t,
    badge: usize,
    grant: bool,
    receiver: *mut tcb_t,
) {
    unsafe {
        do_ipc_transfer(&*sender, Some(&*endpoint), badge, grant, &mut *receiver)
    }
}


fn do_fault_reply(receiver: &mut tcb_t, sender: &mut tcb_t) -> bool {
    let tag = seL4_MessageInfo_t::from_word_security(sender.get_register(msgInfoRegister));
    let label = tag.get_label();
    let length = tag.get_length();
    match receiver.tcbFault.get_fault_type() {
        FaultType::UnknownSyscall => {
            sender.copy_fault_mrs_for_reply(receiver, MessageID_Syscall, core::cmp::min(length, n_syscallMessage));
            return label as usize == 0;
        }
        FaultType::UserException => {
            sender.copy_fault_mrs_for_reply(receiver, MessageID_Exception, core::cmp::min(length, n_exceptionMessage));
            return label as usize == 0;
        }
        _ => true
    }
}

#[inline]
pub fn do_reply_transfer(sender: &mut tcb_t, receiver: &mut tcb_t, slot: &mut cte_t, grant: bool) {
    assert_eq!(receiver.get_state(), ThreadState::ThreadStateBlockedOnReply);
    let fault_type = receiver.tcbFault.get_fault_type();
    if likely(fault_type == FaultType::NullFault) {
        do_ipc_transfer(sender, None, 0, grant, receiver);
        slot.delete_one();
        set_thread_state(receiver, ThreadState::ThreadStateRunning);
        possible_switch_to(receiver);
    } else {
        slot.delete_one();
        if do_fault_reply(receiver, sender) {
            set_thread_state(receiver, ThreadState::ThreadStateRestart);
            possible_switch_to(receiver);
        } else {
            set_thread_state(receiver, ThreadState::ThreadStateInactive);
        }
    }
}