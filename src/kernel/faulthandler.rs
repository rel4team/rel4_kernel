
use task_manager::*;
use crate::syscall::handle_fault;

#[no_mangle]
pub fn handleFault(tptr: *mut tcb_t) {
    unsafe {
        handle_fault(&mut *tptr);
    }
}
