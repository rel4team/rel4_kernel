use core::intrinsics::unlikely;

use crate::{
    config::{
        msgRegister, n_msgRegisters, thread_control_update_ipc_buffer,
        thread_control_update_mcp, thread_control_update_priority, thread_control_update_space,
        seL4_MinPrio,
    },
    kernel::{
        boot::{current_extra_caps, current_syscall_error},
        thread::getExtraCPtr,
        vspace::{checkValidIPCBuffer, isValidVTableRoot},
    },
    syscall::{getSyscallArg, invokeTCB_ThreadControl},
};

use common::message_info::*;
use task_manager::*;
use ipc::*;
use super::notification::{bindNotification, unbindNotification};

use common::{structures::{exception_t, seL4_IPCBuffer}, sel4_config::*};
use cspace::interface::*;
use log::debug;

#[no_mangle]
pub fn checkPrio(prio: usize, auth: *mut tcb_t) -> exception_t {
    unsafe {
        let mcp = (*auth).tcbMCP;
        if prio > mcp {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = seL4_MinPrio;
            current_syscall_error.rangeErrorMax = mcp;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        exception_t::EXCEPTION_NONE
    }
}

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
pub fn decodeSetMCPriority(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    unsafe {
        if length < 1 || current_extra_caps.excaprefs[0] as usize == 0 {
            debug!("TCB SetMCPPriority: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let newMcp = getSyscallArg(0, buffer);
    let authCap: &cap_t;
    unsafe {
        authCap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(authCap) != cap_thread_cap {
        debug!("SetMCPriority: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let authTCB = cap_thread_cap_get_capTCBPtr(authCap) as *mut tcb_t;
    let status = checkPrio(newMcp, authTCB);
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            debug!(
                "TCB SetMCPriority: Requested maximum controlled priority {} too high (max {}).",
                newMcp,
                (*authTCB).tcbMCP
            );
        }
        return status;
    }
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        0 as *mut cte_t,
        0,
        newMcp,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cap_null_cap_new(),
        0 as *mut cte_t,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        thread_control_update_mcp,
    )
}

#[no_mangle]
pub fn decodeSetSchedParams(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    unsafe {
        if length < 2 || current_extra_caps.excaprefs[0] as usize == 0 {
            debug!("TCB SetSchedParams: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let newMcp = getSyscallArg(0, buffer);
    let newPrio = getSyscallArg(1, buffer);
    let authCap: &cap_t;
    unsafe {
        authCap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(authCap) != cap_thread_cap {
        debug!("SetSchedParams: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let authTCB = cap_thread_cap_get_capTCBPtr(authCap) as *mut tcb_t;
    let mut status = checkPrio(newMcp, authTCB);
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            debug!(
                "TCB SetSchedParams: Requested maximum controlled priority {} too high (max {}).",
                newMcp,
                (*authTCB).tcbMCP
            );
            return status;
        }
    }
    status = checkPrio(newPrio, authTCB);
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            debug!(
                "TCB SetSchedParams: Requested priority {} too high (max {}).",
                newPrio,
                (*authTCB).tcbMCP
            );
            return status;
        }
    }
    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        0 as *mut cte_t,
        0,
        newMcp,
        newPrio,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cap_null_cap_new(),
        0 as *mut cte_t,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        thread_control_update_mcp | thread_control_update_priority,
    )
}

#[no_mangle]
pub fn decodeSetIPCBuffer(
    cap: &cap_t,
    length: usize,
    slot: *mut cte_t,
    buffer: *mut usize,
) -> exception_t {
    unsafe {
        if length < 1 || current_extra_caps.excaprefs[0] as usize == 0 {
            debug!("TCB SetIPCBuffer: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let cptr_bufferPtr = getSyscallArg(0, buffer);
    let mut bufferSlot: *mut cte_t;
    let mut bufferCap: &cap_t;
    let dc_ret: deriveCap_ret;
    unsafe {
        bufferSlot = current_extra_caps.excaprefs[0] as *mut cte_t;
        bufferCap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cptr_bufferPtr == 0 {
        bufferSlot = 0 as *mut cte_t;
    } else {
        dc_ret = deriveCap(bufferSlot, bufferCap);
        if dc_ret.status != exception_t::EXCEPTION_NONE {
            unsafe {
                current_syscall_error._type = seL4_IllegalOperation;
            }
            return dc_ret.status;
        }
        bufferCap = &dc_ret.cap;
        let e = checkValidIPCBuffer(cptr_bufferPtr, bufferCap);
        if e != exception_t::EXCEPTION_NONE {
            return e;
        }
    }
    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        slot,
        0,
        0,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cptr_bufferPtr,
        bufferCap.clone(),
        bufferSlot,
        thread_control_update_ipc_buffer,
    )
}

#[no_mangle]
pub fn decodeSetSpace(
    cap: &cap_t,
    length: usize,
    slot: *mut cte_t,
    buffer: *mut usize,
) -> exception_t {
    unsafe {
        if length < 3
            || current_extra_caps.excaprefs[0] as usize == 0
            || current_extra_caps.excaprefs[1] as usize == 0
        {
            debug!("TCB SetSpace: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let faultEP = getSyscallArg(0, buffer);
    let cRootData = getSyscallArg(1, buffer);
    let vRootData = getSyscallArg(2, buffer);

    let cRootSlot: *mut cte_t;
    let mut cRootCap: cap_t;
    let vRootSlot: *mut cte_t;
    let mut vRootCap: cap_t;
    unsafe {
        cRootSlot = current_extra_caps.excaprefs[0];
        cRootCap = (*current_extra_caps.excaprefs[0]).cap.clone();
        vRootSlot = current_extra_caps.excaprefs[1];
        vRootCap = (*current_extra_caps.excaprefs[1]).cap.clone();
    }

    unsafe {
        if slotCapLongRunningDelete(getCSpace(cap_thread_cap_get_capTCBPtr(cap), tcbCTable))
            || slotCapLongRunningDelete(getCSpace(cap_thread_cap_get_capTCBPtr(cap), tcbVTable))
        {
            debug!("TCB Configure: CSpace or VSpace currently being deleted.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if cRootData as usize != 0 {
        cRootCap = updateCapData(false, cRootData, &mut cRootCap).clone();
    }
    let dc_ret1 = deriveCap(cRootSlot, &cRootCap);
    if dc_ret1.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return dc_ret1.status;
    }
    cRootCap = dc_ret1.cap.clone();
    if cap_get_capType(&cRootCap) != cap_cnode_cap {
        debug!("TCB Configure: CSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if vRootData as usize != 0 {
        vRootCap = updateCapData(false, vRootData, &mut vRootCap);
    }
    let dc_ret = deriveCap(vRootSlot, &vRootCap);
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return dc_ret.status;
    }
    vRootCap = dc_ret.cap.clone();
    if !isValidVTableRoot(&vRootCap) {
        debug!("TCB Configure: VSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }

    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        slot as *mut cte_t,
        faultEP,
        0,
        0,
        cRootCap.clone(),
        cRootSlot as *mut cte_t,
        vRootCap.clone(),
        vRootSlot as *mut cte_t,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        thread_control_update_space,
    )
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
pub fn decodeSetPriority(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    unsafe {
        if length < 1 || current_extra_caps.excaprefs[0] as usize == 0 {
            debug!("TCB SetPriority: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let newPrio = getSyscallArg(0, buffer);
    let authCap: &cap_t;
    unsafe {
        authCap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(authCap) != cap_thread_cap {
        debug!("Set priority: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let authTCB = cap_thread_cap_get_capTCBPtr(authCap) as *mut tcb_t;
    let status = checkPrio(newPrio, authTCB);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        0 as *mut cte_t,
        0,
        0,
        newPrio,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cap_null_cap_new(),
        0 as *mut cte_t,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        thread_control_update_priority,
    )
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