use sel4_common::arch::n_syscallMessage;
use sel4_task::*;

#[no_mangle]
pub fn process3(sender: *mut tcb_t, receiver: *mut tcb_t, _receiveIPCBuffer: *mut usize) -> usize {
    unsafe {
        (*sender).copy_syscall_fault_mrs(&mut *receiver);
        (*receiver).set_mr(
            n_syscallMessage,
            (*sender).tcbFault.unknown_syscall_get_syscall_number(),
        )
    }
}
