use crate::{config::{n_msgRegisters, msgRegister, seL4_MinPrio}, kernel::boot::current_syscall_error};
use common::{MASK, sel4_config::{seL4_IPCBufferSizeBits, seL4_AlignmentError}};
use common::{structures::{seL4_IPCBuffer, exception_t}, sel4_config::{seL4_RangeError, seL4_IllegalOperation}, IS_ALIGNED};
use cspace::interface::{cap_t, CapTag};
use ipc::{notification_ptr_set_ntfnBoundTCB, notification_t, notification_ptr_get_ntfnBoundTCB};
use log::debug;
use task_manager::*;

#[inline]
#[no_mangle]
pub fn getSyscallArg(i: usize, ipc_buffer: *const usize) -> usize {
    unsafe {
        if i < n_msgRegisters {
            return getRegister(ksCurThread, msgRegister[i]);
        } else {
            assert!(ipc_buffer as usize != 0);
            let ptr = ipc_buffer.add(i + 1);
            return *ptr;
        }
    }
}

#[inline]
pub fn get_syscall_arg(i: usize, ipc_buffer: Option<&seL4_IPCBuffer>) -> usize {
    if i < n_msgRegisters {
        return get_currenct_thread().get_register(msgRegister[i]);
    }
    return ipc_buffer.unwrap().msg[i];
}

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

#[inline]
pub fn check_prio(prio: usize, auth_tcb: &tcb_t) -> exception_t {
    if prio > auth_tcb.tcbMCP {
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = seL4_MinPrio;
            current_syscall_error.rangeErrorMax = auth_tcb.tcbMCP;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn check_ipc_buffer_vaild(vptr: usize, cap: &cap_t) -> exception_t {
    if cap.get_cap_type() != CapTag::CapFrameCap {
        debug!("Requested IPC Buffer is not a frame cap.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if cap.get_frame_is_device() != 0 {
        debug!("Specifying a device frame as an IPC buffer is not permitted.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if !IS_ALIGNED!(vptr, seL4_IPCBufferSizeBits) {
        debug!("Requested IPC Buffer location 0x%x is not aligned.");
        unsafe { current_syscall_error._type = seL4_AlignmentError; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn bindNotification(tcb: *mut tcb_t, ptr: *mut notification_t) {
    notification_ptr_set_ntfnBoundTCB(ptr, tcb as usize);
    unsafe {
        (*tcb).tcbBoundNotification = ptr as *mut notification_t as usize;
    }
    unsafe {
        (*ptr).bind_tcb(&mut *tcb)
    }
}

#[inline]
pub fn do_unbind_notification(tcb: &mut tcb_t, nftn: &mut notification_t) {
    nftn.unbind_tcb();
    tcb.unbind_notification();
}

#[no_mangle]
pub fn doUnbindNotification(tcb: *mut tcb_t, ptr: *mut notification_t) {
    unsafe {
        do_unbind_notification(&mut *tcb, &mut *ptr)
    }
}

#[no_mangle]
pub fn unbindMaybeNotification(ptr: *const notification_t) {
    let tcb: *mut tcb_t = notification_ptr_get_ntfnBoundTCB(ptr) as *mut tcb_t;
    if tcb as usize != 0 {
        doUnbindNotification(tcb, ptr as *mut notification_t);
    }
}

#[no_mangle]
pub fn unbindNotification(tcb: *mut tcb_t) {
    unsafe {
        let ptr = (*tcb).tcbBoundNotification;
        if ptr != 0 {
            doUnbindNotification(tcb, ptr as *mut notification_t);
        }
    }
}