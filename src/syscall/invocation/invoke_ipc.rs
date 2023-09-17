use common::structures::exception_t;
use ipc::endpoint_t;
use task_manager::ksCurThread;

use crate::object::endpoint::sendIPC;


#[no_mangle]
pub fn performInvocation_Endpoint(
    ep: *const endpoint_t,
    badge: usize,
    canGrant: bool,
    canGrantReply: bool,
    block: bool,
    call: bool,
) -> exception_t {
    sendIPC(
        block,
        call,
        badge,
        canGrant,
        canGrantReply,
        unsafe { ksCurThread },
        ep as *mut endpoint_t,
    );
    exception_t::EXCEPTION_NONE
}
