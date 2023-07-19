use core::{arch::asm, intrinsics::unlikely};

use crate::{
    config::{
        irqInvalid, maxIRQ, seL4_IllegalOperation, seL4_InvalidCapability, seL4_RangeError,
        seL4_RevokeFirst, seL4_TruncatedMessage, IRQAckIRQ, IRQClearIRQHandler, IRQInactive,
        IRQIssueIRQHandler, IRQReserved, IRQSetIRQHandler, IRQSignal, IRQTimer,
        RISCVIRQIssueIRQHandlerTrigger, ThreadStateRestart, KERNEL_TIMER_IRQ, SIE_STIE, SIP_SEIP,
        SIP_STIP,
    },
    kernel::{
        boot::{active_irq, current_extra_caps, current_syscall_error},
        cspace::rust_lookupTargetSlot,
        thread::{getExtraCPtr, ksCurThread, setThreadState, timerTick},
    },
    println,
    riscv::{read_sip, resetTimer},
    structures::notification_t,
    syscall::getSyscallArg,
    BIT,
};

use super::{
    cap::{cteDeleteOne, ensureEmptySlot},
    notification::sendSignal,
};

use common::structures::exception_t;
use cspace::interface::*;

#[no_mangle]
pub static mut intStateIRQTable: [usize; 2] = [0; 2];

pub static mut intStateIRQNode: usize = 0;

#[no_mangle]
pub extern "C" fn intStateIRQNodeToR(ptr: *mut usize) {
    unsafe {
        intStateIRQNode = ptr as usize;
    }
}

#[inline]
pub fn set_sie_mask(mask_high: usize) {
    unsafe {
        let _temp: usize;
        asm!("csrrs {0},sie,{1}",out(reg)_temp,in(reg)mask_high);
    }
}
#[inline]
pub fn clear_sie_mask(mask_low: usize) {
    unsafe {
        let _temp: usize;
        asm!("csrrc {0},sie,{1}",out(reg)_temp,in(reg)mask_low);
    }
}

#[inline]
pub fn maskInterrupt(disable: bool, irq: usize) {
    if irq == KERNEL_TIMER_IRQ {
        if disable {
            clear_sie_mask(BIT!(SIE_STIE));
        } else {
            set_sie_mask(BIT!(SIE_STIE));
        }
    }
}

pub fn isIRQPending() -> bool {
    let sip = read_sip();
    if (sip & (BIT!(SIP_STIP) | BIT!(SIP_SEIP))) != 0 {
        true
    } else {
        false
    }
}

#[no_mangle]
pub fn deletingIRQHandler(irq: usize) {
    unsafe {
        let slot = (intStateIRQNode as *mut cte_t).add(irq);
        cteDeleteOne(slot);
    }
}

#[no_mangle]
pub fn setIRQState(state: usize, irq: usize) {
    unsafe {
        intStateIRQTable[irq] = state;
        maskInterrupt(state == 0, irq);
    }
}

#[no_mangle]
pub fn invokeIRQControl(
    irq: usize,
    handlerSlot: *mut cte_t,
    controlSlot: *mut cte_t,
) -> exception_t {
    setIRQState(IRQSignal, irq);
    cteInsert(&cap_irq_handler_cap_new(irq), controlSlot, handlerSlot);
    exception_t::EXCEPTION_NONE
}

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
pub fn ackInterrupt(_irq: usize) {
    unsafe {
        active_irq[0] = irqInvalid;
    }
}

#[no_mangle]
pub fn isIRQActive(irq: usize) -> bool {
    unsafe { intStateIRQTable[irq] != IRQInactive }
}

#[no_mangle]
pub fn Arch_checkIRQ(irq: usize) -> exception_t {
    if irq > maxIRQ || irq == irqInvalid {
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = maxIRQ;
            println!(
                "Rejecting request for IRQ {}. IRQ is out of range [1..maxIRQ].",
                irq
            );
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn Arch_decodeIRQControlInvocation(
    invLabel: usize,
    length: usize,
    srcSlot: *mut cte_t,
    buffer: *mut usize,
) -> exception_t {
    if invLabel == RISCVIRQIssueIRQHandlerTrigger {
        unsafe {
            if length < 4 || current_extra_caps.excaprefs[0] as usize == 0 {
                current_syscall_error._type = seL4_TruncatedMessage;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        let irq = getSyscallArg(0, buffer);
        let trigger = getSyscallArg(1, buffer) != 0;
        let index = getSyscallArg(2, buffer);
        let depth = getSyscallArg(3, buffer);

        let cnodeCap = unsafe { (*current_extra_caps.excaprefs[0]).cap.clone() };

        let status = Arch_checkIRQ(irq);

        if status != exception_t::EXCEPTION_NONE {
            return status;
        }

        if isIRQActive(irq) {
            unsafe {
                current_syscall_error._type = seL4_RevokeFirst;
                println!("Rejecting request for IRQ {}. Already active.", irq);
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }

        let lu_ret = rust_lookupTargetSlot(&cnodeCap, index, depth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            println!(
                "Target slot for new IRQ Handler cap invalid: cap {:#x}, IRQ {}.",
                getExtraCPtr(buffer, 0),
                irq
            );
            return lu_ret.status;
        }
        let destSlot = lu_ret.slot;
        unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
        }
        return Arch_invokeIRQControl(irq, destSlot, srcSlot, trigger);
    } else {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
}

#[no_mangle]
pub fn Arch_invokeIRQControl(
    irq: usize,
    handlerSlot: *mut cte_t,
    controlSlot: *mut cte_t,
    _trigger: bool,
) -> exception_t {
    invokeIRQControl(irq, handlerSlot, controlSlot)
}

#[no_mangle]
pub fn decodeIRQControlInvocation(
    invLabel: usize,
    length: usize,
    srcSlot: *mut cte_t,
    buffer: *mut usize,
) -> exception_t {
    if invLabel == IRQIssueIRQHandler {
        unsafe {
            if length < 3 || current_extra_caps.excaprefs[0] as usize == 0 {
                current_syscall_error._type = seL4_TruncatedMessage;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        let irq = getSyscallArg(0, buffer);
        let index = getSyscallArg(1, buffer);
        let depth = getSyscallArg(2, buffer);

        let cnodeCap = unsafe { (*current_extra_caps.excaprefs[0]).cap.clone() };

        let status = Arch_checkIRQ(irq);

        if status != exception_t::EXCEPTION_NONE {
            return status;
        }

        if isIRQActive(irq) {
            unsafe {
                current_syscall_error._type = seL4_RevokeFirst;
                println!("Rejecting request for IRQ {}. Already active.", irq);
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }

        let lu_ret = rust_lookupTargetSlot(&cnodeCap, index, depth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            println!(
                "Target slot for new IRQ Handler cap invalid: cap {:#x}, IRQ {}.",
                getExtraCPtr(buffer, 0),
                irq
            );
            return lu_ret.status;
        }
        let destSlot = lu_ret.slot;

        let status = ensureEmptySlot(destSlot);
        if status != exception_t::EXCEPTION_NONE {
            println!(
                "Target slot for new IRQ Handler cap not empty: cap {}, IRQ {}.",
                getExtraCPtr(buffer, 0),
                irq
            );
        }

        unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
        }
        return invokeIRQControl(irq, destSlot, srcSlot);
    } else {
        return Arch_decodeIRQControlInvocation(invLabel, length, srcSlot, buffer);
    }
}

#[no_mangle]
pub fn handleInterrupt(irq: usize) {
    if unlikely(irq > maxIRQ) {
        println!(
            "Received IRQ {}, which is above the platforms maxIRQ of {}\n",
            irq, maxIRQ
        );
        maskInterrupt(true, irq);
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
                    sendSignal(
                        cap_notification_cap_get_capNtfnPtr(cap) as *mut notification_t,
                        cap_notification_cap_get_capNtfnBadge(cap),
                    );
                }
            }
            IRQTimer => {
                timerTick();
                resetTimer();
            }
            IRQReserved => {
                println!("Received unhandled reserved IRQ: {}\n", irq);
            }
            IRQInactive => {
                maskInterrupt(true, irq);
                println!("Received disabled IRQ: {}\n", irq);
            }
            _ => {
                panic!("invalid IRQ state");
            }
        }
    }
    ackInterrupt(irq);
}

#[no_mangle]
pub fn decodeIRQHandlerInvocation(invLabel: usize, irq: usize) -> exception_t {
    match invLabel {
        IRQAckIRQ => unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
            return exception_t::EXCEPTION_NONE;
        },
        IRQSetIRQHandler => unsafe {
            if current_extra_caps.excaprefs[0] as usize == 0 {
                current_syscall_error._type = seL4_TruncatedMessage;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let ntfnCap = &(*current_extra_caps.excaprefs[0]).cap;
            let slot = current_extra_caps.excaprefs[0];

            if cap_get_capType(ntfnCap) != cap_notification_cap
                || cap_notification_cap_get_capNtfnCanSend(ntfnCap) == 0
            {
                if cap_get_capType(ntfnCap) != cap_notification_cap {
                    println!("IRQSetHandler: provided cap is not an notification capability.");
                } else {
                    println!("IRQSetHandler: caller does not have send rights on the endpoint.");
                }
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 0;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            setThreadState(ksCurThread, ThreadStateRestart);
            invokeIRQHandler_SetIRQHandler(irq, ntfnCap, slot);
            return exception_t::EXCEPTION_NONE;
        },
        IRQClearIRQHandler => unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
            invokeIRQHandler_ClearIRQHandler(irq);
            return exception_t::EXCEPTION_NONE;
        },
        _ => unsafe {
            println!("IRQHandler: Illegal operation.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        },
    }
}
