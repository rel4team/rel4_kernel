use crate::{
    config::badgeRegister,
    kernel::thread::doNBRecvFailedTransfer,
};
use cspace::compatibility::*;
use task_manager::*;
use ipc::*;

use cspace::interface::*;

#[no_mangle]
pub fn completeSignal(ptr: *mut notification_t, tcb: *mut tcb_t) {
    if tcb as usize != 0 && notification_ptr_get_state(ptr) == NtfnState_Active {
        let badge = notification_ptr_get_ntfnMsgIdentifier(ptr);
        setRegister(tcb, badgeRegister, badge);
        notification_ptr_set_state(ptr, NtfnState_Idle);
    } else {
        panic!("tried to complete signal with inactive notification object");
    }
}


#[no_mangle]
pub fn receiveSignal(thread: *mut tcb_t, cap: &cap_t, isBlocking: bool) {
    let ntfnPtr = cap_notification_cap_get_capNtfnPtr(cap) as *mut notification_t;
    match notification_ptr_get_state(ntfnPtr) {
        NtfnState_Idle | NtfnState_Waiting => unsafe {
            if isBlocking {
                thread_state_set_tsType(&mut (*thread).tcbState, ThreadStateBlockedOnNotification);
                thread_state_set_blockingObject(&mut (*thread).tcbState, ntfnPtr as usize);
                scheduleTCB(thread);
                let mut queue = ntfn_ptr_get_queue(ntfnPtr);
                queue = tcbEPAppend(thread, queue);
                notification_ptr_set_state(ntfnPtr, NtfnState_Waiting);
                ntfn_ptr_set_queue(ntfnPtr, queue);
            } else {
                doNBRecvFailedTransfer(thread);
            }
        },
        NtfnState_Active => {
            setRegister(
                thread,
                badgeRegister,
                notification_ptr_get_ntfnMsgIdentifier(ntfnPtr),
            );
            notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
        }
        _ => panic!(
            "Invalid Notification state:{}",
            notification_ptr_get_state(ntfnPtr)
        ),
    }
}
