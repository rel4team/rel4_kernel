use crate::{kernel::thread::{tcbEPAppend,  setThreadState, tcbEPDequeue}, structures::{tcb_t, thread_state_t, endpoint_t, tcb_queue_t}, config::{ThreadStateBlockedOnSend, EPState_Idle, EPState_Send}};

use super::structure_gen::{endpoint_ptr_set_state, thread_state_set_blockingIPCIsCall, thread_state_set_blockingIPCCanGrantReply, thread_state_set_blockingIPCBadge, thread_state_set_blockingIPCCanGrant, thread_state_set_blockingObject, endpoint_ptr_get_state, thread_state_set_tsType, endpoint_ptr_get_epQueue_head, endpoint_ptr_get_epQueue_tail, endpoint_ptr_set_epQueue_head, endpoint_ptr_set_epQueue_tail};

#[inline]
pub fn ep_ptr_set_queue(epptr: *const endpoint_t, queue: tcb_queue_t) {
    endpoint_ptr_set_epQueue_head(epptr as *mut endpoint_t, queue.head);
    endpoint_ptr_set_epQueue_tail(epptr as *mut endpoint_t, queue.tail);
}

#[inline]
pub fn ep_ptr_get_queue(epptr: *const endpoint_t) -> tcb_queue_t {
    let queue = tcb_queue_t {
        head: endpoint_ptr_get_epQueue_head(epptr as *mut endpoint_t),
        tail: endpoint_ptr_get_epQueue_tail(epptr as *mut endpoint_t),
    };

    queue
}

// #[no_mangle]
// pub fn sendIPC(
//     blocking: bool,
//     do_call: bool,
//     badge: usize,
//     canGrant: bool,
//     canGrantReply: bool,
//     thread: *mut tcb_t,
//     epptr: *mut endpoint_t,
// ) {
//     unsafe {
//         match endpoint_ptr_get_state(epptr) {
//             EPState_Idle | EPState_Send => {
//                 if blocking {
//                     // println!("waiting in sendIPC , epptr:{:#x}",epptr as usize);
//                     thread_state_set_tsType(
//                         (*thread).tcbState as *mut thread_state_t,
//                         ThreadStateBlockedOnSend,
//                     );
//                     thread_state_set_blockingObject(
//                         (*thread).tcbState as *mut thread_state_t,
//                         epptr as usize,
//                     );
//                     thread_state_set_blockingIPCCanGrant(
//                         (*thread).tcbState as *mut thread_state_t,
//                         canGrant as usize,
//                     );
//                     thread_state_set_blockingIPCBadge(
//                         (*thread).tcbState as *mut thread_state_t,
//                         badge,
//                     );
//                     thread_state_set_blockingIPCCanGrantReply(
//                         (*thread).tcbState as *mut thread_state_t,
//                         canGrantReply as usize,
//                     );
//                     thread_state_set_blockingIPCIsCall(
//                         (*thread).tcbState as *mut thread_state_t,
//                         do_call as usize,
//                     );

//                     scheduleTCB(thread as *const tcb_t);

//                     let mut queue = ep_ptr_get_queue(epptr);
//                     queue = tcbEPAppend(thread as *mut tcb_t, queue);
//                     endpoint_ptr_set_state(epptr, EPState_Send);
//                     ep_ptr_set_queue(epptr, queue);
//                 }
//             }
//             EPState_Recv => {
//                 let mut queue = ep_ptr_get_queue(epptr);
//                 assert!(queue.head != 0);
//                 let dest = queue.head as *mut tcb_t;
//                 queue = tcbEPDequeue(dest, queue);

//                 if queue.head != 0 {
//                     endpoint_ptr_set_state(epptr, EPState_Idle);
//                 }
//                 // println!("in sendIPC ,  thread:{:#x} , dest:{:#x}",thread as usize,dest as usize);
//                 doIPCTransfer(thread, epptr, badge, canGrant, dest);
//                 let replyCanGrant = if thread_state_get_blockingIPCCanGrant((*dest).tcbState) != 0 {
//                     true
//                 } else {
//                     false
//                 };
//                 setThreadState(dest, ThreadStateRunning);
//                 possibleSwitchTo(dest);
//                 if do_call {
//                     if canGrant || canGrantReply {
//                         setupCallerCap(thread, dest, replyCanGrant);
//                     } else {
//                         setThreadState(thread, ThreadStateInactive);
//                     }
//                 }
//             }
//             _ => {
//                 panic!(
//                     "unknown epptr state in sendIPC(): {}",
//                     endpoint_ptr_get_state(epptr)
//                 );
//             }
//         }
//     }
// }
