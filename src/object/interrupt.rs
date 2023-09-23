use core::intrinsics::unlikely;

use crate::{
    config::maxIRQ,
    kernel::boot::{current_extra_caps, current_syscall_error},
    riscv::resetTimer,
    interrupt::*,
};

use common::{message_info::*, utils::convert_to_mut_type_ref};

use cspace::compatibility::*;
use common::{structures::exception_t, sel4_config::*};
use cspace::interface::*;
use ipc::*;
use task_manager::*;
use log::debug;


#[no_mangle]
pub fn invokeIRQHandler_SetIRQHandler(irq: usize, cap: &cap_t, slot: *mut cte_t) {
    let irqSlot = unsafe { (intStateIRQNode as *mut cte_t).add(irq) };
        cteDeleteOne(irqSlot);
    cteInsert(cap, slot, irqSlot);
}

#[no_mangle]
pub fn invokeIRQHandler_ClearIRQHandler(irq: usize) {
    let irqSlot = unsafe { (intStateIRQNode as *mut cte_t).add(irq) };
    cteDeleteOne(irqSlot);
}

#[no_mangle]
pub fn deletedIRQHandler(irq: usize) {
    setIRQState(IRQInactive, irq);
}


#[no_mangle]
pub fn handleInterrupt(irq: usize) {
    if unlikely(irq > maxIRQ) {
        debug!(
            "Received IRQ {}, which is above the platforms maxIRQ of {}\n",
            irq, maxIRQ
        );
        mask_interrupt(true, irq);
        ackInterrupt(irq);
        return;
    }

    unsafe {
        match intStateIRQTable[irq] {
            IRQSignal => {
                let cte_ptr = (intStateIRQNode as *mut cte_t).add(irq);
                let cap = &(*cte_ptr).cap;
                if cap_get_capType(cap) == cap_notification_cap
                    && cap_notification_cap_get_capNtfnCanSend(cap) != 0
                {
                    convert_to_mut_type_ref::<notification_t>(cap.get_nf_ptr()).send_signal(cap.get_nf_badge());
                }
            }
            IRQTimer => {
                timerTick();
                resetTimer();
            }
            IRQReserved => {
                debug!("Received unhandled reserved IRQ: {}\n", irq);
            }
            IRQInactive => {
                mask_interrupt(true, irq);
                debug!("Received disabled IRQ: {}\n", irq);
            }
            _ => {
                panic!("invalid IRQ state");
            }
        }
    }
    ackInterrupt(irq);
}

#[no_mangle]
pub fn decodeIRQHandlerInvocation(invLabel: MessageLabel, irq: usize) -> exception_t {
    match invLabel {
        MessageLabel::IRQAckIRQ => unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
            return exception_t::EXCEPTION_NONE;
        },
        MessageLabel::IRQSetIRQHandler => unsafe {
            if current_extra_caps.excaprefs[0] as usize == 0 {
                current_syscall_error._type = seL4_TruncatedMessage;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let ntfnCap = &(*(current_extra_caps.excaprefs[0] as *mut cte_t)).cap;
            let slot = current_extra_caps.excaprefs[0] as *mut cte_t;

            if cap_get_capType(ntfnCap) != cap_notification_cap
                || cap_notification_cap_get_capNtfnCanSend(ntfnCap) == 0
            {
                if cap_get_capType(ntfnCap) != cap_notification_cap {
                    debug!("IRQSetHandler: provided cap is not an notification capability.");
                } else {
                    debug!("IRQSetHandler: caller does not have send rights on the endpoint.");
                }
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 0;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            setThreadState(ksCurThread, ThreadStateRestart);
            invokeIRQHandler_SetIRQHandler(irq, ntfnCap, slot);
            return exception_t::EXCEPTION_NONE;
        },
        MessageLabel::IRQClearIRQHandler => unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
            invokeIRQHandler_ClearIRQHandler(irq);
            return exception_t::EXCEPTION_NONE;
        },
        _ => unsafe {
            debug!("IRQHandler: Illegal operation.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        },
    }
}
