mod decode_tcb_invocation;
mod decode_domain_invocation;
mod decode_cnode_invocation;
mod decode_untyped_invocation;
mod decode_mmu_invocation;
pub mod decode_irq_control_invocation;

use core::intrinsics::unlikely;

use common::{structures::{exception_t, seL4_IPCBuffer}, sel4_config::seL4_InvalidCapability, utils::{convert_to_mut_type_ref, convert_to_option_type_ref}, message_info::MessageLabel};
use cspace::interface::{cte_t, cap_t, CapTag};
use ipc::{endpoint_t, notification_t, transfer::do_reply_transfer};
use log::debug;
use task_manager::{set_thread_state, get_currenct_thread, ThreadState, tcb_t};

use crate::{
    kernel::boot::current_syscall_error, 
    object::interrupt::{decodeIRQHandlerInvocation}
};

use self::{
    decode_tcb_invocation::decode_tcb_invocation, 
    decode_domain_invocation::decode_domain_invocation,
    decode_cnode_invocation::decode_cnode_invocation,
    decode_untyped_invocation::decode_untyed_invocation,
    decode_mmu_invocation::decode_mmu_invocation, decode_irq_control_invocation::decode_irq_control_invocation,
};


#[no_mangle]
pub fn decodeInvocation(
    invLabel: MessageLabel,
    length: usize,
    capIndex: usize,
    slot: *mut cte_t,
    cap: &mut cap_t,
    block: bool,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    match cap.get_cap_type() {
        CapTag::CapNullCap | CapTag::CapZombieCap  => {
            debug!("Attempted to invoke a null or zombie cap {:#x}, {:?}.", capIndex, cap.get_cap_type());
            unsafe {
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 0;
            }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }

        CapTag::CapEndpointCap => {
            if unlikely(cap.get_ep_can_send() == 0) {
                debug!("Attempted to invoke a read-only endpoint cap {}.", capIndex);
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            convert_to_mut_type_ref::<endpoint_t>(cap.get_ep_ptr()).send_ipc(block, get_currenct_thread(),
                call, cap.get_ep_can_grant() != 0, cap.get_ep_badge(), cap.get_ep_can_grant_reply() != 0);
            return exception_t::EXCEPTION_NONE;
        }

        CapTag::CapNotificationCap => {
            if unlikely(cap.get_nf_can_send() == 0) {
                debug!(
                    "Attempted to invoke a read-only notification cap {}.",
                    capIndex
                );
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            convert_to_mut_type_ref::<notification_t>(cap.get_nf_ptr()).send_signal(cap.get_nf_badge());
            exception_t::EXCEPTION_NONE
        }

        CapTag::CapReplyCap => {
            if unlikely(cap.get_reply_master() != 0) {
                debug!("Attempted to invoke an invalid reply cap {}.", capIndex);
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            // return performInvocation_Reply(
            //     convert_to_mut_type_ref::<tcb_t>(cap.get_reply_tcb_ptr()),
            //     slot,
            //     cap.get_reply_can_grant() != 0,
            // );
            do_reply_transfer(get_currenct_thread(), convert_to_mut_type_ref::<tcb_t>(cap.get_reply_tcb_ptr()),
                unsafe { &mut *slot }, cap.get_reply_can_grant() != 0);
            exception_t::EXCEPTION_NONE
        }
        CapTag::CapThreadCap => decode_tcb_invocation(invLabel, length, cap, unsafe { &mut *slot }, call, convert_to_option_type_ref::<seL4_IPCBuffer>(buffer as usize)),
        CapTag::CapDomainCap => decode_domain_invocation(invLabel, length, convert_to_option_type_ref::<seL4_IPCBuffer>(buffer as usize)),
        CapTag::CapCNodeCap => decode_cnode_invocation(invLabel, length, cap, convert_to_option_type_ref::<seL4_IPCBuffer>(buffer as usize)),
        CapTag::CapUntypedCap => decode_untyed_invocation(invLabel, length, unsafe { &mut *slot }, cap, convert_to_option_type_ref::<seL4_IPCBuffer>(buffer as usize)),
        CapTag::CapIrqControlCap => decode_irq_control_invocation(invLabel, length, unsafe { &mut *slot }, convert_to_option_type_ref::<seL4_IPCBuffer>(buffer as usize)),
        CapTag::CapIrqHandlerCap => {
            decodeIRQHandlerInvocation(invLabel, cap.get_irq_handler())
        }
        _ => {
            decode_mmu_invocation(invLabel, length, unsafe { &mut *slot }, call, convert_to_option_type_ref::<seL4_IPCBuffer>(buffer as usize))
        }
    }
}