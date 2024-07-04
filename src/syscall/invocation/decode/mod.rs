mod decode_cnode_invocation;
mod decode_domain_invocation;
pub mod decode_irq_invocation;
mod decode_mmu_invocation;
mod decode_tcb_invocation;
mod decode_untyped_invocation;

use core::intrinsics::unlikely;

use log::debug;
use sel4_common::{
    message_info::MessageLabel,
    sel4_config::seL4_InvalidCapability,
    structures::{exception_t, seL4_IPCBuffer},
    utils::convert_to_mut_type_ref,
};
use sel4_cspace::interface::{cap_t, cte_t, CapTag};
use sel4_ipc::{endpoint_t, notification_t, Transfer};
use sel4_task::{get_currenct_thread, set_thread_state, tcb_t, ThreadState};

use crate::kernel::boot::current_syscall_error;
use crate::syscall::invocation::decode::decode_irq_invocation::decode_irq_handler_invocation;

use self::{
    decode_cnode_invocation::decode_cnode_invocation,
    decode_domain_invocation::decode_domain_invocation,
    decode_irq_invocation::decode_irq_control_invocation,
    decode_mmu_invocation::decode_mmu_invocation, decode_tcb_invocation::decode_tcb_invocation,
    decode_untyped_invocation::decode_untyed_invocation,
};

pub fn decode_invocation(
    label: MessageLabel,
    length: usize,
    slot: &mut cte_t,
    cap: &cap_t,
    cap_index: usize,
    block: bool,
    call: bool,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    match cap.get_cap_type() {
        CapTag::CapNullCap | CapTag::CapZombieCap => {
            debug!(
                "Attempted to invoke a null or zombie cap {:#x}, {:?}.",
                cap_index,
                cap.get_cap_type()
            );
            unsafe {
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 0;
            }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }

        CapTag::CapEndpointCap => {
            if unlikely(cap.get_ep_can_send() == 0) {
                debug!(
                    "Attempted to invoke a read-only endpoint cap {}.",
                    cap_index
                );
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            convert_to_mut_type_ref::<endpoint_t>(cap.get_ep_ptr()).send_ipc(
                get_currenct_thread(),
                block,
                call,
                cap.get_ep_can_grant() != 0,
                cap.get_ep_badge(),
                cap.get_ep_can_grant_reply() != 0,
            );
            return exception_t::EXCEPTION_NONE;
        }

        CapTag::CapNotificationCap => {
            if unlikely(cap.get_nf_can_send() == 0) {
                debug!(
                    "Attempted to invoke a read-only notification cap {}.",
                    cap_index
                );
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            convert_to_mut_type_ref::<notification_t>(cap.get_nf_ptr())
                .send_signal(cap.get_nf_badge());
            exception_t::EXCEPTION_NONE
        }

        CapTag::CapReplyCap => {
            if unlikely(cap.get_reply_master() != 0) {
                debug!("Attempted to invoke an invalid reply cap {}.", cap_index);
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            get_currenct_thread().do_reply(
                convert_to_mut_type_ref::<tcb_t>(cap.get_reply_tcb_ptr()),
                slot,
                cap.get_reply_can_grant() != 0,
            );
            exception_t::EXCEPTION_NONE
        }
        CapTag::CapThreadCap => decode_tcb_invocation(label, length, cap, slot, call, buffer),
        CapTag::CapDomainCap => decode_domain_invocation(label, length, buffer),
        CapTag::CapCNodeCap => decode_cnode_invocation(label, length, cap, buffer),
        CapTag::CapUntypedCap => decode_untyed_invocation(label, length, slot, cap, buffer),
        CapTag::CapIrqControlCap => decode_irq_control_invocation(label, length, slot, buffer),
        CapTag::CapIrqHandlerCap => decode_irq_handler_invocation(label, cap.get_irq_handler()),
        _ => decode_mmu_invocation(label, length, slot, call, buffer),
    }
}
