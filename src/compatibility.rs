use sel4_common::structures::seL4_IPCBuffer;
use sel4_cspace::interface::{cap_t, cte_t};
use sel4_task::{set_thread_state, tcb_t, ThreadState};
use sel4_vspace::{pte_t, vptr_t};

#[inline]
#[no_mangle]
pub fn isMDBParentOf() {
    panic!("should not be invoked!")
}

#[no_mangle]
pub fn deriveCap(_slot: *mut cte_t, _cap: &cap_t) {
    panic!("should not be invoked!")
}

#[no_mangle]
pub fn setThreadState(tptr: *mut tcb_t, ts: usize) {
    // panic!("should not be invoked!")
    unsafe {
        set_thread_state(
            &mut *tptr,
            core::mem::transmute::<u8, ThreadState>(ts as u8),
        )
    }
}

#[no_mangle]
pub fn setupReplyMaster(_thread: *mut tcb_t) {
    panic!("should not be invoked")
}

#[no_mangle]
pub fn lookupIPCBuffer(isReceiver: bool, thread: *mut tcb_t) -> usize {
    unsafe {
        match (*thread).lookup_ipc_buffer(isReceiver) {
            Some(ipc_buffer) => return ipc_buffer as *const seL4_IPCBuffer as usize,
            _ => 0,
        }
    }
}

#[no_mangle]
pub fn pte_next(_phys_addr: usize, _is_leaf: bool) -> pte_t {
    panic!("should not be invoked!")
}

#[no_mangle]
pub fn isPTEPageTable(_pte: *mut pte_t) -> bool {
    panic!("should not be invoked!")
}

#[no_mangle]
pub extern "C" fn lookupPTSlot(_lvl1pt: *mut pte_t, _vptr: vptr_t) {
    panic!("should not be invoked!")
}
