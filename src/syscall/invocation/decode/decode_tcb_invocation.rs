use common::{message_info::MessageLabel, structures::exception_t, sel4_config::{seL4_IllegalOperation, seL4_TruncatedMessage, seL4_RangeError}, BIT};
use cspace::interface::{cap_t, cte_t};
use log::debug;
use task_manager::{tcb_t, set_thread_state, get_currenct_thread, ThreadState};

use crate::{object::tcb::{decodeWriteRegisters, decodeCopyRegisters, invokeTCB_Suspend, invokeTCB_Resume, 
    decodeTCBConfigure, decodeSetPriority, decodeSetMCPriority, decodeSetSchedParams, decodeSetIPCBuffer, decodeSetSpace, 
    decodeBindNotification, decodeUnbindNotification, decodeSetTLSBase}, 
    kernel::boot::current_syscall_error, syscall::getSyscallArg, config::{n_frameRegisters, n_gpRegisters, ReadRegisters_suspend}, utils::convert_to_mut_type_ref};

use super::super::invoke_tcb::invokeTCB_ReadRegisters;

#[no_mangle]
pub fn decodeTCBInvocation(
    invLabel: MessageLabel,
    length: usize,
    cap: &cap_t,
    slot: *mut cte_t,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    match invLabel {
        MessageLabel::TCBReadRegisters => decodeReadRegisters(cap, length, call, buffer),
        MessageLabel::TCBWriteRegisters => decodeWriteRegisters(cap, length, buffer),
        MessageLabel::TCBCopyRegisters => decodeCopyRegisters(cap, length, buffer),
        MessageLabel::TCBSuspend => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invokeTCB_Suspend(cap.get_tcb_ptr() as *mut tcb_t)
        }
        MessageLabel::TCBResume => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invokeTCB_Resume(cap.get_tcb_ptr() as *mut tcb_t)
        }
        MessageLabel::TCBConfigure => decodeTCBConfigure(cap, length, slot, buffer),
        MessageLabel::TCBSetPriority => decodeSetPriority(cap, length, buffer),
        MessageLabel::TCBSetMCPriority => decodeSetMCPriority(cap, length, buffer),
        MessageLabel::TCBSetSchedParams => decodeSetSchedParams(cap, length, buffer),
        MessageLabel::TCBSetIPCBuffer => decodeSetIPCBuffer(cap, length, slot as *mut cte_t, buffer),
        MessageLabel::TCBSetSpace => decodeSetSpace(cap, length, slot as *mut cte_t, buffer),
        MessageLabel::TCBBindNotification => decodeBindNotification(cap),
        MessageLabel::TCBUnbindNotification => decodeUnbindNotification(cap),
        MessageLabel::TCBSetTLSBase => decodeSetTLSBase(cap, length, buffer),
        _ => unsafe {
            debug!("TCB: Illegal operation invLabel :{:?}", invLabel);
            current_syscall_error._type = seL4_IllegalOperation;
            exception_t::EXCEPTION_SYSCALL_ERROR
        },
    }
}


#[no_mangle]
pub fn decodeReadRegisters(
    cap: &cap_t,
    length: usize,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    if length < 2 {
        unsafe {
            debug!("TCB CopyRegisters: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let flags = getSyscallArg(0, buffer);
    let n = getSyscallArg(1, buffer);
    if n < 1 || n > n_frameRegisters + n_gpRegisters {
        debug!(
            "TCB ReadRegisters: Attempted to read an invalid number of registers:{}",
            n
        );
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = n_frameRegisters + n_gpRegisters;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        // let thread = cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t;
        let thread = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
        if thread .is_current() {
            debug!("TCB ReadRegisters: Attempted to read our own registers.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }

        // setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
        set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
        invokeTCB_ReadRegisters(
            thread,
            flags & BIT!(ReadRegisters_suspend),
            n,
            0,
            call,
        )
    }
}