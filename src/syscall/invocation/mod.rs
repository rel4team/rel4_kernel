pub mod decode;
mod invoke_cnode;
pub mod invoke_irq;
mod invoke_mmu_op;
mod invoke_tcb;
mod invoke_untyped;

use core::intrinsics::unlikely;

use log::debug;
use sel4_common::arch::{msgRegisterNum, ArchReg};
use sel4_common::{fault::seL4_Fault_t, message_info::seL4_MessageInfo_t, structures::exception_t};
use sel4_task::{get_currenct_thread, set_thread_state, ThreadState};

use crate::kernel::boot::current_fault;
use crate::syscall::invocation::decode::decode_invocation;
use crate::syscall::syscall_reply::{reply_error_from_kernel, reply_success_from_kernel};
use crate::syscall::{handle_fault, lookup_extra_caps_with_buf};

#[no_mangle]
pub fn handleInvocation(isCall: bool, isBlocking: bool) -> exception_t {
    let thread = get_currenct_thread();
    let info =
        seL4_MessageInfo_t::from_word_security(thread.tcbArch.get_register(ArchReg::MsgInfo));
    let cptr = thread.tcbArch.get_register(ArchReg::Cap);
    let lu_ret = thread.lookup_slot(cptr);
    if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("Invocation of invalid cap {:#x}.", cptr);
        unsafe {
            current_fault = seL4_Fault_t::new_cap_fault(cptr, 0);
        }
        if isBlocking {
            handle_fault(thread);
        }
        return exception_t::EXCEPTION_NONE;
    }
    let buffer = thread.lookup_ipc_buffer(false);
    let status = lookup_extra_caps_with_buf(thread, buffer);
    if unlikely(status != exception_t::EXCEPTION_NONE) {
        debug!("Lookup of extra caps failed.");
        if isBlocking {
            // handleFault(thread);
            handle_fault(thread);
        }
        return exception_t::EXCEPTION_NONE;
    }

    let mut length = info.get_length();
    if unlikely(length > msgRegisterNum && buffer.is_none()) {
        length = msgRegisterNum;
    }

    let cap = unsafe { (*(lu_ret.slot)).cap };
    let status = decode_invocation(
        info.get_label(),
        length,
        unsafe { &mut *lu_ret.slot },
        &cap,
        cptr,
        isBlocking,
        isCall,
        buffer,
    );
    if status == exception_t::EXCEPTION_PREEMTED {
        return status;
    }

    if status == exception_t::EXCEPTION_SYSCALL_ERROR {
        if isCall {
            reply_error_from_kernel(thread);
        }
        return exception_t::EXCEPTION_NONE;
    }

    if unlikely(thread.get_state() == ThreadState::ThreadStateRestart) {
        if isCall {
            reply_success_from_kernel(thread);
        }
        set_thread_state(thread, ThreadState::ThreadStateRunning);
    }
    return exception_t::EXCEPTION_NONE;
}
