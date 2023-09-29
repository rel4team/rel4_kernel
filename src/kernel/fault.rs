

use task_manager::*;


#[no_mangle]
pub fn process3(sender: *mut tcb_t, receiver: *mut tcb_t, _receiveIPCBuffer: *mut usize) -> usize {
    unsafe {
        (*sender).copy_syscall_fault_mrs(&mut *receiver);
        // setMR(
        //     receiver,
        //     receiveIPCBuffer,
        //     n_syscallMessage,
        //     seL4_Fault_UnknownSyscall_get_syscallNumber(&(*sender).tcbFault),
        // )
        (*receiver).set_mr(n_syscallMessage, (*sender).tcbFault.unknown_syscall_get_syscall_number())
    }
}