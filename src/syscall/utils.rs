use crate::{config::{n_msgRegisters, msgRegister}, kernel::thread::getRegister};

use crate::task_manager::*;

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