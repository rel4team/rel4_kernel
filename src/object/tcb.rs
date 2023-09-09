use core::intrinsics::unlikely;

use crate::{
    config::{
        msgRegister, n_msgRegisters,
    },
    kernel::{
        boot::{current_extra_caps, current_syscall_error},
        thread::getExtraCPtr,
    },
    syscall::{getSyscallArg, bindNotification, unbindNotification},
};

use common::message_info::*;
use task_manager::*;
use ipc::*;

use common::{structures::{exception_t, seL4_IPCBuffer}, sel4_config::*};
use cspace::interface::*;
use log::debug;

#[no_mangle]
pub fn lookupExtraCaps(
    thread: *mut tcb_t,
    bufferPtr: *mut usize,
    info: &seL4_MessageInfo_t,
) -> exception_t {
    unsafe {
        if bufferPtr as usize == 0 {
            current_extra_caps.excaprefs[0] = 0 as *mut cte_t;
            return exception_t::EXCEPTION_NONE;
        }
        let length = seL4_MessageInfo_ptr_get_extraCaps(info as *const seL4_MessageInfo_t);
        let mut i = 0;
        while i < length {
            let cptr = getExtraCPtr(bufferPtr, i);
            let lu_ret = lookupSlot(thread, cptr);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                panic!(" lookup slot error , found slot :{}", lu_ret.slot as usize);
            }
            current_extra_caps.excaprefs[i] = lu_ret.slot;
            i += 1;
        }
        if i < seL4_MsgMaxExtraCaps {
            current_extra_caps.excaprefs[i] = 0 as *mut cte_t;
        }
        return exception_t::EXCEPTION_NONE;
    }
}

pub fn lookup_extra_caps(thread: &tcb_t, op_buffer: Option<&seL4_IPCBuffer>, info: &seL4_MessageInfo_t) -> exception_t {
    match op_buffer {
        Some(buffer) => {
            let length = info.get_extra_caps();
            let mut i = 0;
            while i < length {
                let cptr = buffer.get_extra_cptr(i);
                let lu_ret = thread.lookup_slot(cptr);
                if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE)  {
                    panic!(" lookup slot error , found slot :{}", lu_ret.slot as usize);
                }
                unsafe {
                    current_extra_caps.excaprefs[i] = lu_ret.slot;
                }
                i += 1;
            }
            if i < seL4_MsgMaxExtraCaps {
                unsafe {
                    current_extra_caps.excaprefs[i] = 0 as *mut cte_t;
                }
            }
        }
        _ => {
            unsafe {
                current_extra_caps.excaprefs[0] = 0 as *mut cte_t;
            }
        }
    }
    return exception_t::EXCEPTION_NONE;
}

#[no_mangle]
pub fn copyMRs(
    sender: *mut tcb_t,
    sendBuf: *mut usize,
    receiver: *mut tcb_t,
    recvBuf: *mut usize,
    n: usize,
) -> usize {
    let mut i = 0;
    while i < n && i < n_msgRegisters {
        setRegister(
            receiver,
            msgRegister[i],
            getRegister(sender, msgRegister[i]),
        );
        i += 1;
    }

    if recvBuf as usize == 0 || sendBuf as usize == 0 {
        return i;
    }

    while i < n {
        unsafe {
            let recvPtr = recvBuf.add(i + 1);
            let sendPtr = sendBuf.add(i + 1);
            *recvPtr = *sendPtr;
            i += 1;
        }
    }
    i
}

#[no_mangle]
pub fn decodeBindNotification(cap: &cap_t) -> exception_t {
    unsafe {
        if current_extra_caps.excaprefs[0] as usize == 0 {
            debug!("TCB BindNotification: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let tcb = cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t;
    let ntfnPtr: *mut notification_t;
    unsafe {
        if (*tcb).tcbBoundNotification != 0 {
            debug!("TCB BindNotification: TCB already has a bound notification.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let ntfn_cap: &cap_t;
    unsafe {
        ntfn_cap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(ntfn_cap) == cap_notification_cap {
        ntfnPtr = cap_notification_cap_get_capNtfnPtr(ntfn_cap) as *mut notification_t;
    } else {
        debug!("TCB BindNotification: Notification is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    if cap_notification_cap_get_capNtfnCanReceive(ntfn_cap) == 0 {
        debug!("TCB BindNotification: Insufficient access rights");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if notification_ptr_get_ntfnQueue_head(ntfnPtr) != 0
        || notification_ptr_get_ntfnQueue_tail(ntfnPtr) != 0
    {
        debug!("TCB BindNotification: Notification cannot be bound.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_NotificationControl(tcb, ntfnPtr)
}

#[no_mangle]
pub fn invokeTCB_NotificationControl(tcb: *mut tcb_t, ntfnPtr: *mut notification_t) -> exception_t {
    if ntfnPtr as usize != 0 {
        bindNotification(tcb, ntfnPtr);
    } else {
        unbindNotification(tcb);
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn decodeUnbindNotification(cap: &cap_t) -> exception_t {
    let tcb = cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t;
    unsafe {
        if (*tcb).tcbBoundNotification == 0 {
            debug!("TCB BindNotification: TCB already has a bound notification.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_NotificationControl(tcb, 0 as *mut notification_t)
}

#[no_mangle]
pub fn invokeSetTLSBase(thread: *mut tcb_t, base: usize) -> exception_t {
    setRegister(thread, TLS_BASE, base);
    unsafe {
        if thread == ksCurThread {
            rescheduleRequired();
        }
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn decodeSetTLSBase(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    if length < 1 {
        debug!("TCB SetTLSBase: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let base = getSyscallArg(0, buffer);
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
    }
    invokeSetTLSBase(cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t, base)
}