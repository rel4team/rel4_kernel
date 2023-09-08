use crate::config::{n_msgRegisters, msgRegister};

use common::structures::seL4_IPCBuffer;
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