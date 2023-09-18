use core::intrinsics::unlikely;

use crate::{
    config::{
        irqInvalid, maxIRQ, KERNEL_TIMER_IRQ, SIP_SEIP, SIP_STIP,
    },
    object::{
        endpoint::receiveIPC,
        interrupt::handleInterrupt,
        notification::receiveSignal,
    },
    riscv::read_sip,
};
use cspace::compatibility::*;
use super::{
    boot::{active_irq, current_fault, current_lookup_fault},
    faulthandler::handleFault,
    thread::doReplyTransfer,
    vspace::handleVMFault, cspace::lookupCap,
};

use common::{structures::exception_t, BIT, sel4_config::tcbCaller, fault::*};
use log::debug;
use task_manager::*;
use ipc::*;

#[no_mangle]
pub fn handleInterruptEntry() -> exception_t {
    let irq = getActiveIRQ();
    if irq != irqInvalid {
        handleInterrupt(irq);
    } else {
        debug!("Spurious interrupt!");
        debug!("Superior IRQ!! SIP {:#x}\n", read_sip());
    }

    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn handleUserLevelFault(w_a: usize, w_b: usize) -> exception_t {
    unsafe {
        current_fault = seL4_Fault_UserException_new(w_a, w_b);
        handleFault(ksCurThread);
    }
    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn handleVMFaultEvent(vm_faultType: usize) -> exception_t {
    let status = unsafe { handleVMFault(ksCurThread, vm_faultType) };
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            handleFault(ksCurThread);
        }
    }
    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

pub fn IS_IRQ_VALID(x: usize) -> bool {
    (x <= maxIRQ) && (x != irqInvalid)
}

#[inline]
#[no_mangle]
pub fn getActiveIRQ() -> usize {
    let mut irq = unsafe { active_irq[0] };
    if IS_IRQ_VALID(irq) {
        return irq;
    }

    let sip = read_sip();
    if (sip & BIT!(SIP_SEIP)) != 0 {
        irq = 0;
    } else if (sip & BIT!(SIP_STIP)) != 0 {
        irq = KERNEL_TIMER_IRQ;
    } else {
        irq = irqInvalid;
    }
    unsafe {
        active_irq[0] = irq;
    }
    return irq;
}


#[no_mangle]
pub fn handleReply() {
    let callerSlot = unsafe { getCSpace(ksCurThread as usize, tcbCaller) };
    let callerCap = unsafe { &(*callerSlot).cap };

    match cap_get_capType(callerCap) {
        cap_reply_cap => {
            if cap_reply_cap_get_capReplyMaster(callerCap) != 0 {
                return;
            }
            let caller = cap_reply_cap_get_capTCBPtr(callerCap) as *mut tcb_t;
            unsafe {
                doReplyTransfer(
                    ksCurThread,
                    caller,
                    callerSlot,
                    cap_reply_cap_get_capReplyCanGrant(callerCap) != 0,
                );
            }
            return;
        }
        _ => return,
    }
}

#[no_mangle]
pub fn handleYield() {
    unsafe {
        tcbSchedDequeue(ksCurThread);
        tcbSchedAppend(ksCurThread);
        rescheduleRequired();
    }
}

#[no_mangle]
pub fn handleRecv(isBlocking: bool) {
    let epCptr = unsafe { getRegister(ksCurThread, capRegister) };
    let lu_ret = unsafe { lookupCap(ksCurThread, epCptr) };
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_fault = seL4_Fault_CapFault_new(epCptr, 1);
            handleFault(ksCurThread);
            return;
        }
    }
    match cap_get_capType(&lu_ret.cap) {
        cap_endpoint_cap => {
            if unlikely(cap_endpoint_cap_get_capCanReceive(&lu_ret.cap) == 0) {
                unsafe {
                    current_lookup_fault = lookup_fault_missing_capability_new(0);
                    current_fault = seL4_Fault_CapFault_new(epCptr, 1);
                    handleFault(ksCurThread);
                    return;
                }
            }
            unsafe {
                deleteCallerCap(ksCurThread);
                receiveIPC(ksCurThread, &lu_ret.cap, isBlocking);
            }
        }
        cap_notification_cap => {
            let ntfnPtr = cap_notification_cap_get_capNtfnPtr(&lu_ret.cap) as *mut notification_t;
            let boundTCB = notification_ptr_get_ntfnBoundTCB(ntfnPtr) as *mut tcb_t;
            unsafe {
                if unlikely(
                    cap_notification_cap_get_capNtfnCanReceive(&lu_ret.cap) == 0
                        || (boundTCB as usize != 0 && boundTCB != ksCurThread),
                ) {
                    current_fault = seL4_Fault_CapFault_new(epCptr, 1);
                    current_lookup_fault = lookup_fault_missing_capability_new(0);
                    handleFault(ksCurThread);
                    return;
                }
                receiveSignal(ksCurThread, &lu_ret.cap, isBlocking);
                return;
            }
        }
        _ => unsafe {
            current_lookup_fault = lookup_fault_missing_capability_new(0);
            current_fault = seL4_Fault_CapFault_new(epCptr, 1);
            handleFault(ksCurThread);
            return;
        },
    }
}

