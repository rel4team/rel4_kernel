pub mod decode;
mod invoke_tcb;
mod invoke_cnode;
mod invoke_untyped;
pub mod invoke_mmu_op;

use core::intrinsics::unlikely;

use common::{structures::{exception_t, seL4_Fault_CapFault_new}, message_info::seL4_MessageInfo_t};
use log::debug;
use task_manager::{get_currenct_thread, msgInfoRegister, capRegister, ThreadState, set_thread_state, n_msgRegisters};

use crate::{kernel::{boot::current_fault, faulthandler::handleFault}, object::{tcb::lookup_extra_caps, endpoint::{replyFromKernel_error, replyFromKernel_success_empty}},
    utils::ipc_buf_ref_to_usize_ptr};

use self::decode::decodeInvocation;


#[no_mangle]
pub fn handleInvocation(isCall: bool, isBlocking: bool) -> exception_t {
    let thread = get_currenct_thread();
    let info = seL4_MessageInfo_t::from_word_security(thread.get_register(msgInfoRegister));
    let cptr = thread.get_register(capRegister);
    let lu_ret = thread.lookup_slot(cptr);
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
    let buffer = thread.lookup_ipc_buffer(false);
    let status = lookup_extra_caps(thread, buffer, &info);
    if unlikely(status != exception_t::EXCEPTION_NONE) {
        debug!("Lookup of extra caps failed.");
        if isBlocking {
            handleFault(thread);
        }
        return exception_t::EXCEPTION_NONE;
    }

    let mut length = info.get_length();
    if unlikely(length > n_msgRegisters && buffer.is_none()) {
        length = n_msgRegisters;
    }

    let mut cap = unsafe {(*(lu_ret.slot)).cap};
    let status = decodeInvocation(
        info.get_label(),
        length,
        cptr,
        lu_ret.slot,
        &mut cap,
        isBlocking,
        isCall,
        ipc_buf_ref_to_usize_ptr(buffer),
    );
    // let _ = buffer.unwrap();

    if status == exception_t::EXCEPTION_PREEMTED {
        return status;
    }

    if status == exception_t::EXCEPTION_SYSCALL_ERROR {
        if isCall {
            replyFromKernel_error(thread);
        }
        return exception_t::EXCEPTION_NONE;
    }

    if unlikely(thread.get_state() == ThreadState::ThreadStateRestart) {
        if isCall {
            replyFromKernel_success_empty(thread);
        }
        set_thread_state(thread, ThreadState::ThreadStateRunning);
    }
    return exception_t::EXCEPTION_NONE;
}