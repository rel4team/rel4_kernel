

use task_manager::*;

use common::fault::*;


use super::thread::setMR;

#[no_mangle]
pub fn process3(sender: *mut tcb_t, receiver: *mut tcb_t, receiveIPCBuffer: *mut usize) -> usize {
    unsafe {
        (*sender).copy_syscall_fault_mrs(&mut *receiver);
        setMR(
            receiver,
            receiveIPCBuffer,
            n_syscallMessage,
            seL4_Fault_UnknownSyscall_get_syscallNumber(&(*sender).tcbFault),
        )
    }
}