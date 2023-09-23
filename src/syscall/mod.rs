mod utils;
pub mod invocation;

use core::intrinsics::unlikely;

pub const SysCall: isize = -1;
pub const SysReplyRecv: isize = -2;
pub const SysSend: isize = -3;
pub const SysNBSend: isize = -4;
pub const SysRecv: isize = -5;
pub const SysReply: isize = -6;
pub const SysYield: isize = -7;
pub const SysNBRecv: isize = -8;
use common::structures::exception_t;
use task_manager::{schedule, activateThread};
pub use utils::*;

use crate::{kernel::{syscall::{handleRecv, handleReply, handleYield}, c_traps::restore_user_context}, config::irqInvalid, object::interrupt::handleInterrupt, interrupt::getActiveIRQ};

use self::invocation::handleInvocation;


#[link(name = "kernel_all.c")]
extern "C" {
    pub fn handleUnknownSyscall(w: usize);
}

#[no_mangle]
pub fn slowpath(syscall: usize) {
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