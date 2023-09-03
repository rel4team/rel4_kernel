use core::intrinsics::unlikely;

use crate::{
    config::{
        irqInvalid, maxIRQ, msgInfoRegister, n_msgRegisters, SysCall, SysNBRecv,
        SysNBSend, SysRecv, SysReply, SysReplyRecv, SysSend, SysYield, KERNEL_TIMER_IRQ, SIP_SEIP, SIP_STIP,
    },
    object::{
        endpoint::{receiveIPC, replyFromKernel_error, replyFromKernel_success_empty},
        interrupt::handleInterrupt,
        notification::receiveSignal,
        objecttype::decodeInvocation,
        tcb::lookupExtraCaps,
    },
    riscv::read_sip,
    structures::seL4_MessageInfo_t,
};

use super::{
    boot::{active_irq, current_fault, current_lookup_fault},
    faulthandler::handleFault,
    thread::doReplyTransfer,
    transfermsg::{
        messageInfoFromWord, seL4_MessageInfo_ptr_get_label, seL4_MessageInfo_ptr_get_length,
    },
    vspace::{handleVMFault, lookupIPCBuffer}, cspace::{lookupCap, lookupCapAndSlot},
};

use common::{structures::{exception_t, lookup_fault_missing_capability_new, seL4_Fault_UserException_new,
    seL4_Fault_CapFault_new}, BIT, sel4_config::tcbCaller};
use cspace::interface::*;
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
pub fn handleInvocation(isCall: bool, isBlocking: bool) -> exception_t {
    let thread = unsafe { ksCurThread };
    let info = messageInfoFromWord(getRegister(thread, msgInfoRegister));
    let cptr = getRegister(thread, capRegister);
    let mut lu_ret = lookupCapAndSlot(thread, cptr);

    if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("Invocation of invalid cap {:#x}.", cptr);
        unsafe {
            current_fault = seL4_Fault_CapFault_new(cptr, 0);
        }
        if isBlocking {
            handleFault(thread);
        }
        return exception_t::EXCEPTION_NONE;
    }
    let buffer = lookupIPCBuffer(false, thread) as *mut usize;
    let status = lookupExtraCaps(thread, buffer, &info);

    if unlikely(status != exception_t::EXCEPTION_NONE) {
        debug!("Lookup of extra caps failed.");
        if isBlocking {
            handleFault(thread);
        }
        return exception_t::EXCEPTION_NONE;
    }

    let mut length = seL4_MessageInfo_ptr_get_length(&info as *const seL4_MessageInfo_t);

    if unlikely(length > n_msgRegisters && buffer as usize == 0) {
        length = n_msgRegisters;
    }
    let status = decodeInvocation(
        seL4_MessageInfo_ptr_get_label(&info as *const seL4_MessageInfo_t),
        length,
        cptr,
        lu_ret.slot,
        &mut lu_ret.cap,
        isBlocking,
        isCall,
        buffer,
    );

    if status == exception_t::EXCEPTION_PREEMTED {
        return status;
    }

    if status == exception_t::EXCEPTION_SYSCALL_ERROR {
        if isCall {
            replyFromKernel_error(thread);
        }
        return exception_t::EXCEPTION_NONE;
    }

    unsafe {
        if unlikely(thread_state_get_tsType(&(*thread).tcbState) == ThreadStateRestart) {
            if isCall {
                replyFromKernel_success_empty(thread);
            }
            setThreadState(thread, ThreadStateRunning);
        }
    }
    return exception_t::EXCEPTION_NONE;
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

#[no_mangle]
pub fn handleSyscall(_syscall: usize) -> exception_t {
    let syscall: isize = _syscall as isize;
    match syscall {
        SysSend => {
            let ret = handleInvocation(false, true);

            if unlikely(ret != exception_t::EXCEPTION_NONE) {
                let irq = getActiveIRQ();
                if irq != irqInvalid {
                    handleInterrupt(irq);
                }
            }
        }
        SysNBSend => {
            let ret = handleInvocation(false, false);
            if unlikely(ret != exception_t::EXCEPTION_NONE) {
                let irq = getActiveIRQ();
                if irq != irqInvalid {
                    handleInterrupt(irq);
                }
            }
        }
        SysCall => {
            let ret = handleInvocation(true, true);
            if unlikely(ret != exception_t::EXCEPTION_NONE) {
                let irq = getActiveIRQ();
                if irq != irqInvalid {
                    handleInterrupt(irq);
                }
            }
        }
        SysRecv => {
            handleRecv(true);
        }
        SysReply => handleReply(),
        SysReplyRecv => {
            handleReply();
            handleRecv(true);
        }
        SysNBRecv => handleRecv(false),
        SysYield => handleYield(),
        _ => panic!("Invalid syscall"),
    }
    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}
