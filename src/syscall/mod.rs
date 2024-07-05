pub mod invocation;
pub mod syscall_reply;
pub mod utils;

use core::intrinsics::unlikely;
use sel4_common::arch::ArchReg;
use sel4_common::fault::{lookup_fault_t, seL4_Fault_t, FaultType};
use sel4_common::sel4_config::tcbCaller;

pub const SysCall: isize = -1;
pub const SysReplyRecv: isize = -2;
pub const SysSend: isize = -3;
pub const SysNBSend: isize = -4;
pub const SysRecv: isize = -5;
pub const SysReply: isize = -6;
pub const SysYield: isize = -7;
pub const SysNBRecv: isize = -8;
use crate::ffi::handleUnknownSyscall;
use sel4_common::structures::exception_t;
use sel4_common::utils::convert_to_mut_type_ref;
use sel4_cspace::interface::CapTag;
use sel4_ipc::{endpoint_t, notification_t, Transfer};
use sel4_task::{
    activateThread, get_currenct_thread, rescheduleRequired, schedule, set_thread_state, tcb_t,
    ThreadState,
};
pub use utils::*;

use crate::arch::restore_user_context;
use crate::interrupt::handler::handleInterrupt;
use crate::kernel::boot::{current_fault, current_lookup_fault};
use crate::{config::irqInvalid, interrupt::getActiveIRQ};

use self::invocation::handleInvocation;

#[no_mangle]
pub fn slowpath(syscall: usize) {
    // debug!("enter slow path: {}", syscall as isize);
    if (syscall as isize) < -8 || (syscall as isize) > -1 {
        unsafe {
            handleUnknownSyscall(syscall);
        }
    } else {
        handleSyscall(syscall);
    }
    restore_user_context();
}

#[no_mangle]
pub fn handleSyscall(_syscall: usize) -> exception_t {
    let syscall: isize = _syscall as isize;
    // if hart_id() == 0 {
    //     debug!("handle syscall: {}", syscall);
    // }
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
            handle_recv(true);
        }
        SysReply => handle_reply(),
        SysReplyRecv => {
            handle_reply();
            handle_recv(true);
        }
        SysNBRecv => handle_recv(false),
        SysYield => handle_yield(),
        _ => panic!("Invalid syscall"),
    }
    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

fn send_fault_ipc(thread: &mut tcb_t) -> exception_t {
    let origin_lookup_fault = unsafe { current_lookup_fault };
    let lu_ret = thread.lookup_slot(thread.tcbFaultHandler);
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_fault = seL4_Fault_t::new_cap_fault(thread.tcbFaultHandler, 0);
        }
        return exception_t::EXCEPTION_FAULT;
    }
    let handler_cap = &unsafe { (*lu_ret.slot).cap };
    if handler_cap.get_cap_type() == CapTag::CapEndpointCap
        && (handler_cap.get_ep_can_grant() != 0 || handler_cap.get_ep_can_grant_reply() != 0)
    {
        thread.tcbFault = unsafe { current_fault };
        if thread.tcbFault.get_fault_type() == FaultType::CapFault {
            thread.tcbLookupFailure = origin_lookup_fault;
        }
        convert_to_mut_type_ref::<endpoint_t>(handler_cap.get_ep_ptr()).send_ipc(
            thread,
            true,
            true,
            handler_cap.get_ep_can_grant() != 0,
            handler_cap.get_ep_badge(),
            true,
        );
    } else {
        unsafe {
            current_fault = seL4_Fault_t::new_cap_fault(thread.tcbFaultHandler, 0);
            current_lookup_fault = lookup_fault_t::new_missing_cap(0);
        }
        return exception_t::EXCEPTION_FAULT;
    }
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn handle_fault(thread: &mut tcb_t) {
    if send_fault_ipc(thread) != exception_t::EXCEPTION_NONE {
        // debug!("send_fault_ipc fail");
        set_thread_state(thread, ThreadState::ThreadStateInactive);
    }
}

fn handle_reply() {
    let current_thread = get_currenct_thread();
    let caller_slot = current_thread.get_cspace_mut_ref(tcbCaller);
    let caller_cap = &caller_slot.cap;
    if caller_cap.get_cap_type() == CapTag::CapReplyCap {
        if caller_cap.get_reply_master() != 0 {
            return;
        }
        let caller = convert_to_mut_type_ref::<tcb_t>(caller_cap.get_reply_tcb_ptr());
        current_thread.do_reply(caller, caller_slot, caller_cap.get_reply_can_grant() != 0);
    }
}

fn handle_recv(block: bool) {
    let current_thread = get_currenct_thread();
    let ep_cptr = current_thread.tcbArch.get_register(ArchReg::Cap);
    let lu_ret = current_thread.lookup_slot(ep_cptr);
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_fault = seL4_Fault_t::new_cap_fault(ep_cptr, 1);
        }
        return handle_fault(current_thread);
    }
    let ipc_cap = unsafe { (*lu_ret.slot).cap };
    match ipc_cap.get_cap_type() {
        CapTag::CapEndpointCap => {
            if unlikely(ipc_cap.get_ep_can_receive() == 0) {
                unsafe {
                    current_lookup_fault = lookup_fault_t::new_missing_cap(0);
                    current_fault = seL4_Fault_t::new_cap_fault(ep_cptr, 1);
                }
                return handle_fault(current_thread);
            }
            current_thread.delete_caller_cap();
            convert_to_mut_type_ref::<endpoint_t>(ipc_cap.get_ep_ptr()).receive_ipc(
                current_thread,
                block,
                ipc_cap.get_ep_can_grant() != 0,
            );
        }

        CapTag::CapNotificationCap => {
            let ntfn = convert_to_mut_type_ref::<notification_t>(ipc_cap.get_nf_ptr());
            let bound_tcb_ptr = ntfn.get_bound_tcb();
            if unlikely(
                ipc_cap.get_nf_can_receive() == 0
                    || (bound_tcb_ptr != 0 && bound_tcb_ptr != current_thread.get_ptr()),
            ) {
                unsafe {
                    current_lookup_fault = lookup_fault_t::new_missing_cap(0);
                    current_fault = seL4_Fault_t::new_cap_fault(ep_cptr, 1);
                }
                return handle_fault(current_thread);
            }
            return ntfn.receive_signal(current_thread, block);
        }
        _ => {
            unsafe {
                current_lookup_fault = lookup_fault_t::new_missing_cap(0);
                current_fault = seL4_Fault_t::new_cap_fault(ep_cptr, 1);
            }
            return handle_fault(current_thread);
        }
    }
}

fn handle_yield() {
    get_currenct_thread().sched_dequeue();
    get_currenct_thread().sched_append();
    rescheduleRequired();
}
