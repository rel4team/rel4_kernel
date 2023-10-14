use core::intrinsics::likely;

use super::super::{tcb_t, ThreadState, set_thread_state, possible_switch_to};
use super::super::registers::*;
use super::endpoint::*;
use super::notification::*;

use crate::common::structures::*;
use crate::common::sel4_config::*;
use crate::common::fault::*;
use crate::common::message_info::*;
use crate::common::utils::*;
use crate::cspace::interface::*;
use crate::vspace::pptr_t;

impl tcb_t {
    pub fn cancel_ipc(&mut self) {
        let state = self.tcbState;
        match self.get_state() {
            ThreadState::ThreadStateBlockedOnSend | ThreadState::ThreadStateBlockedOnReceive => {
                let ep = convert_to_mut_type_ref::<endpoint_t>(state.get_blocking_object());
                assert_ne!(ep.get_state(), EPState::Idle);
                ep.cancel_ipc(self);
            }
            ThreadState::ThreadStateBlockedOnNotification => {
                let ntfn = convert_to_mut_type_ref::<notification_t>(state.get_blocking_object());
                ntfn.cancel_signal(self);
            }

            ThreadState::ThreadStateBlockedOnReply => {
                self.tcbFault = seL4_Fault_t::new_null_fault();
                let slot = self.get_cspace(tcbReply);
                let caller_slot_ptr = slot.cteMDBNode.get_next();
                if caller_slot_ptr != 0 {
                    convert_to_mut_type_ref::<cte_t>(caller_slot_ptr).delete_one()
                }
            }
            _ => {}
        }
    }

    fn set_transfer_caps(&mut self, endpoint: Option<&endpoint_t>, info: &mut seL4_MessageInfo_t, current_extra_caps: &[pptr_t; seL4_MsgMaxExtraCaps]) {
        info.set_extra_caps(0);
        info.set_caps_unwrapped(0);
        let ipc_buffer = self.lookup_mut_ipc_buffer(true);
        if current_extra_caps[0] as usize == 0 || ipc_buffer.is_none() {
            return;
        }
        let buffer = ipc_buffer.unwrap();
        let mut dest_slot = self.get_receive_slot();
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

    fn set_transfer_caps_with_buf(&mut self, endpoint: Option<&endpoint_t>, info: &mut seL4_MessageInfo_t, current_extra_caps: &[pptr_t; seL4_MsgMaxExtraCaps], ipc_buffer: Option<&mut seL4_IPCBuffer>) {
        info.set_extra_caps(0);
        info.set_caps_unwrapped(0);
        // let ipc_buffer = self.lookup_mut_ipc_buffer(true);
        if likely(current_extra_caps[0] as usize == 0 || ipc_buffer.is_none()) {
            return;
        }
        let buffer = ipc_buffer.unwrap();
        let mut dest_slot = self.get_receive_slot();
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

    fn do_fault_transfer(&self, receiver: &mut tcb_t, badge: usize) {
        let sent = match self.tcbFault.get_fault_type() {
            crate::common::fault::FaultType::CapFault => {
                receiver.set_mr(seL4_CapFault_IP, self.get_register(FaultIP));
                receiver.set_mr(seL4_CapFault_Addr, self.tcbFault.cap_fault_get_address());
                receiver.set_mr(seL4_CapFault_InRecvPhase, self.tcbFault.cap_fault_get_in_receive_phase());
                receiver.set_lookup_fault_mrs(seL4_CapFault_LookupFailureType, &self.tcbLookupFailure)
            },
            crate::common::fault::FaultType::UnknownSyscall => {
                self.copy_syscall_fault_mrs(receiver);
                receiver.set_mr(n_syscallMessage, self.tcbFault.unknown_syscall_get_syscall_number())
            },
            crate::common::fault::FaultType::UserException => {
                self.copy_exeception_fault_mrs(receiver);
                receiver.set_mr(n_exceptionMessage, self.tcbFault.user_exeception_get_number());
                receiver.set_mr(n_exceptionMessage + 1, self.tcbFault.user_exeception_get_code())
            },
            crate::common::fault::FaultType::VMFault => {
                receiver.set_mr(seL4_VMFault_IP, self.get_register(FaultIP));
                receiver.set_mr(seL4_VMFault_Addr, self.tcbFault.vm_fault_get_address());
                receiver.set_mr(seL4_VMFault_PrefetchFault, self.tcbFault.vm_fault_get_instruction_fault());
                receiver.set_mr(seL4_VMFault_FSR, self.tcbFault.vm_fault_get_fsr())
            },
            _ => {
                panic!("invalid fault")
            }
        };
        let msg_info = seL4_MessageInfo_t::new(self.tcbFault.get_type(), 0, 0, sent);
        receiver.set_register(msgInfoRegister, msg_info.to_word());
        receiver.set_register(badgeRegister, badge);
    }

    fn do_normal_transfer(&self, receiver: &mut tcb_t, endpoint: Option<&endpoint_t>, badge: usize, can_grant: bool) {
        let mut tag = seL4_MessageInfo_t::from_word_security(self.get_register(msgInfoRegister));
        let mut current_extra_caps = [0; seL4_MsgMaxExtraCaps];
        let send_buffer = self.lookup_ipc_buffer(false);
        // let mut recv_buffer = receiver.lookup_mut_ipc_buffer(true);
        if can_grant {
            // let _ = self.lookup_extra_caps(&mut current_extra_caps);
            let _ = self.lookup_extra_caps_with_buf(&mut current_extra_caps, send_buffer);
        }
        // let msg_transferred = self.copy_mrs(receiver, tag.get_length());
        let msg_transferred = self.copy_mrs_with_buf(receiver, tag.get_length(), send_buffer);

        // do_caps_transfer(&mut tag, endpoint, receiver, &current_extra_caps);
        receiver.set_transfer_caps(endpoint, &mut tag, &current_extra_caps);
        // receiver.set_transfer_caps_with_buf(endpoint, &mut tag, &current_extra_caps, recv_buffer.as_deref_mut());
        tag.set_length(msg_transferred);
        receiver.set_register(msgInfoRegister, tag.to_word());
        receiver.set_register(badgeRegister, badge);
    }

    fn do_fault_reply_transfer(&self, receiver: &mut tcb_t) -> bool {
        let tag = seL4_MessageInfo_t::from_word_security(self.get_register(msgInfoRegister));
        let label = tag.get_label();
        let length = tag.get_length();
        match receiver.tcbFault.get_fault_type() {
            FaultType::UnknownSyscall => {
                self.copy_fault_mrs_for_reply(receiver, MessageID_Syscall, core::cmp::min(length, n_syscallMessage));
                return label as usize == 0;
            }
            FaultType::UserException => {
                self.copy_fault_mrs_for_reply(receiver, MessageID_Exception, core::cmp::min(length, n_exceptionMessage));
                return label as usize == 0;
            }
            _ => true
        }
    }

    pub fn complete_signal(&mut self) -> bool {
        if let Some(ntfn) = convert_to_option_mut_type_ref::<notification_t>(self.tcbBoundNotification) {
            if likely(ntfn.get_state() == NtfnState::Active) {
                self.set_register(badgeRegister, ntfn.get_msg_identifier());
                ntfn.set_state(NtfnState::Idle as usize);
                return true;
            }
        }
        false
    }

    pub fn do_ipc_transfer(&self, receiver: &mut tcb_t, endpoint: Option<&endpoint_t>, badge: usize, grant: bool) {
        if likely(self.tcbFault.get_fault_type() == FaultType::NullFault) {
            self.do_normal_transfer(receiver, endpoint, badge, grant)
        } else {
            self.do_fault_transfer(receiver, badge)
        }
    }

    pub fn do_reply(&self, receiver: &mut tcb_t, slot: &mut cte_t, grant: bool) {
        assert_eq!(receiver.get_state(), ThreadState::ThreadStateBlockedOnReply);
        let fault_type = receiver.tcbFault.get_fault_type();
        if likely(fault_type == FaultType::NullFault) {
            self.do_ipc_transfer(receiver, None, 0, grant);
            slot.delete_one();
            set_thread_state(receiver, ThreadState::ThreadStateRunning);
            possible_switch_to(receiver);
        } else {
            slot.delete_one();
            if self.do_fault_reply_transfer(receiver) {
                set_thread_state(receiver, ThreadState::ThreadStateRestart);
                possible_switch_to(receiver);
            } else {
                set_thread_state(receiver, ThreadState::ThreadStateInactive);
            }
        }
    }
}
