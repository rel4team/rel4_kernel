mod decode_tcb_invocation;
mod decode_domain_invocation;
mod decode_cnode_invocation;
mod decode_untyped_invocation;
mod decode_mmu_invocation;
pub mod decode_irq_invocation;

use core::intrinsics::unlikely;

use crate::common::{structures::{exception_t, seL4_IPCBuffer}, sel4_config::seL4_InvalidCapability, utils::convert_to_mut_type_ref, message_info::MessageLabel};
use crate::cspace::interface::{cte_t, cap_t, CapTag};
use crate::task_manager::ipc::{endpoint_t, notification_t};
use log::debug;
use crate::task_manager::{set_thread_state, get_currenct_thread, ThreadState, tcb_t};

use crate::kernel::boot::current_syscall_error;
use crate::syscall::invocation::decode::decode_irq_invocation::decode_irq_handler_invocation;

use self::{
    decode_tcb_invocation::decode_tcb_invocation,
    decode_domain_invocation::decode_domain_invocation,
    decode_cnode_invocation::decode_cnode_invocation,
    decode_untyped_invocation::decode_untyed_invocation,
    decode_mmu_invocation::decode_mmu_invocation,
    decode_irq_invocation::decode_irq_control_invocation,
};


pub fn decode_invocation(label: MessageLabel, length: usize, slot: &mut cte_t, cap: &cap_t, cap_index: usize,
                        block: bool, call: bool, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    #[cfg(feature = "ENABLE_ASYNC_SYSCALL")]
    if cap.get_cap_type() == CapTag::CapExecutorCap {
        use crate::syscall::async_syscall::decode_executor_invocation;
        return decode_executor_invocation(label, length, slot, cap, cap_index, block, call, buffer);
    }
    match cap.get_cap_type() {
        CapTag::CapNullCap | CapTag::CapZombieCap  => {
            debug!("Attempted to invoke a null or zombie cap {:#x}, {:?}.", cap_index, cap.get_cap_type());
            unsafe {
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 0;
            }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }

        CapTag::CapEndpointCap => {
            if unlikely(cap.get_ep_can_send() == 0) {
                debug!("Attempted to invoke a read-only endpoint cap {}.", cap_index);
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            convert_to_mut_type_ref::<endpoint_t>(cap.get_ep_ptr()).send_ipc(get_currenct_thread(),
                                                                             block,
                                                                             call, cap.get_ep_can_grant() != 0,
                                                                             cap.get_ep_badge(),
                                                                             cap.get_ep_can_grant_reply() != 0);
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
            #[cfg(feature = "ENABLE_UINTC")] {
                if get_currenct_thread().uintr_inner.uist.is_none() {
                    crate::uintc::regiser_sender(cap);
                }
            }
            #[cfg(not(feature = "ENABLE_UINTC"))]
            convert_to_mut_type_ref::<notification_t>(cap.get_nf_ptr()).send_signal(cap.get_nf_badge());
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
                cap.get_reply_can_grant() != 0
            );
            exception_t::EXCEPTION_NONE
        }
        CapTag::CapThreadCap => decode_tcb_invocation(label, length, cap, slot, call, buffer),
        CapTag::CapDomainCap => decode_domain_invocation(label, length, buffer),
        CapTag::CapCNodeCap => decode_cnode_invocation(label, length, cap, buffer),
        CapTag::CapUntypedCap => decode_untyed_invocation(label, length, slot, cap, buffer),
        CapTag::CapIrqControlCap => decode_irq_control_invocation(label, length, slot, buffer),
        CapTag::CapIrqHandlerCap => decode_irq_handler_invocation(label, cap.get_irq_handler()),
        _ => decode_mmu_invocation(label, length, slot, call, buffer)
    }

}