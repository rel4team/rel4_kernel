use log::debug;
use sel4_common::{
    message_info::MessageLabel,
    sel4_config::*,
    structures::{exception_t, seL4_IPCBuffer},
    utils::convert_to_mut_type_ref,
};
use sel4_cspace::interface::{cte_t, CapTag};
use sel4_task::{get_currenct_thread, set_thread_state, ThreadState};

use crate::syscall::invocation::invoke_irq::{invoke_clear_irq_handler, invoke_set_irq_handler};
use crate::{
    config::{irqInvalid, maxIRQ},
    interrupt::is_irq_active,
    kernel::boot::{current_syscall_error, get_extra_cap_by_index},
    syscall::{get_syscall_arg, invocation::invoke_irq::invoke_irq_control, lookupSlotForCNodeOp},
};

pub fn decode_irq_control_invocation(
    label: MessageLabel,
    length: usize,
    src_slot: &mut cte_t,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if label == MessageLabel::IRQIssueIRQHandler {
        if length < 3 || get_extra_cap_by_index(0).is_none() {
            unsafe {
                current_syscall_error._type = seL4_TruncatedMessage;
            }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        let irq = get_syscall_arg(0, buffer);
        let index = get_syscall_arg(1, buffer);
        let depth = get_syscall_arg(2, buffer);

        let cnode_cap = get_extra_cap_by_index(0).unwrap().cap;
        let status = check_irq(irq);
        if status != exception_t::EXCEPTION_NONE {
            return status;
        }
        if is_irq_active(irq) {
            unsafe {
                current_syscall_error._type = seL4_RevokeFirst;
            }
            debug!("Rejecting request for IRQ {}. Already active.", irq);
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        let lu_ret = lookupSlotForCNodeOp(false, &cnode_cap, index, depth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            debug!("Target slot for new IRQ Handler cap invalid: IRQ {}.", irq);
            return lu_ret.status;
        }
        let dest_slot = convert_to_mut_type_ref::<cte_t>(lu_ret.slot as usize);
        if dest_slot.cap.get_cap_type() != CapTag::CapNullCap {
            unsafe {
                current_syscall_error._type = seL4_DeleteFirst;
            }
            debug!("Target slot for new IRQ Handler cap not empty");
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
        invoke_irq_control(
            irq,
            convert_to_mut_type_ref::<cte_t>(lu_ret.slot as usize),
            src_slot,
        )
    } else {
        arch_decode_irq_control_invocation(label, length, src_slot, buffer)
    }
}

pub fn decode_irq_handler_invocation(label: MessageLabel, irq: usize) -> exception_t {
    return match label {
        MessageLabel::IRQAckIRQ => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            exception_t::EXCEPTION_NONE
        }

        MessageLabel::IRQSetIRQHandler => {
            if get_extra_cap_by_index(0).is_none() {
                unsafe {
                    current_syscall_error._type = seL4_TruncatedMessage;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let slot = get_extra_cap_by_index(0).unwrap();
            let ntfn_cap = slot.cap;
            if ntfn_cap.get_cap_type() != CapTag::CapNotificationCap
                || ntfn_cap.get_nf_can_send() == 0
            {
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invoke_set_irq_handler(irq, &ntfn_cap, slot);
            exception_t::EXCEPTION_NONE
        }
        MessageLabel::IRQClearIRQHandler => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invoke_clear_irq_handler(irq);
            exception_t::EXCEPTION_NONE
        }
        _ => {
            debug!("IRQHandler: Illegal operation.");
            unsafe {
                current_syscall_error._type = seL4_IllegalOperation;
            }
            exception_t::EXCEPTION_SYSCALL_ERROR
        }
    };
}

fn arch_decode_irq_control_invocation(
    label: MessageLabel,
    length: usize,
    src_slot: &mut cte_t,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if label == MessageLabel::RISCVIRQIssueIRQHandlerTrigger {
        if length < 4 || get_extra_cap_by_index(0).is_none() {
            unsafe {
                current_syscall_error._type = seL4_TruncatedMessage;
            }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        let irq = get_syscall_arg(0, buffer);
        let _trigger = get_syscall_arg(1, buffer) != 0;
        let index = get_syscall_arg(2, buffer);
        let depth = get_syscall_arg(3, buffer);
        let cnode_cap = get_extra_cap_by_index(0).unwrap().cap;
        let status = check_irq(irq);
        if status != exception_t::EXCEPTION_NONE {
            return status;
        }
        if is_irq_active(irq) {
            unsafe {
                current_syscall_error._type = seL4_RevokeFirst;
            }
            debug!("Rejecting request for IRQ {}. Already active.", irq);
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        let lu_ret = lookupSlotForCNodeOp(false, &cnode_cap, index, depth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            debug!("Target slot for new IRQ Handler cap invalid: IRQ {}.", irq);
            return lu_ret.status;
        }
        set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
        invoke_irq_control(
            irq,
            convert_to_mut_type_ref::<cte_t>(lu_ret.slot as usize),
            src_slot,
        )
    } else {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
}

fn check_irq(irq: usize) -> exception_t {
    if irq > maxIRQ || irq == irqInvalid {
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = maxIRQ;
            debug!(
                "Rejecting request for IRQ {}. IRQ is out of range [1..maxIRQ].",
                irq
            );
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    exception_t::EXCEPTION_NONE
}
