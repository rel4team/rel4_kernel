use crate::{
    config::badgeRegister,
    kernel::thread::doNBRecvFailedTransfer,
};
use cspace::compatibility::*;
use task_manager::*;
use ipc::*;

use common::structures::exception_t;
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
pub fn sendSignal(ntfnPtr: *mut notification_t, badge: usize) {
    match notification_ptr_get_state(ntfnPtr) {
        NtfnState_Idle => unsafe {
            let tcb = notification_ptr_get_ntfnBoundTCB(ntfnPtr) as *mut tcb_t;
            if tcb as usize != 0 {
                if thread_state_get_tsType(&(*tcb).tcbState) == ThreadStateBlockedOnReceive {
                    cancelIPC(tcb);
                    setThreadState(tcb, ThreadStateRunning);
                    setRegister(tcb, badgeRegister, badge);
                    possibleSwitchTo(tcb)
                } else {
                    ntfn_ptr_set_active(ntfnPtr, badge);
                }
            } else {
                ntfn_ptr_set_active(ntfnPtr, badge);
            }
        },
        NtfnState_Waiting => {
            let mut queue = ntfn_ptr_get_queue(ntfnPtr);
            let dest = queue.head as *mut tcb_t;
            assert!(dest as usize != 0);
            queue = tcbEPDequeue(dest, queue);
            let temp = queue.head as usize;
            ntfn_ptr_set_queue(ntfnPtr, queue);
            if temp == 0 {
                notification_ptr_set_state(ntfnPtr as *mut notification_t, NtfnState_Idle);
            }
            setThreadState(dest, ThreadStateRunning);
            setRegister(dest, badgeRegister, badge);
            possibleSwitchTo(dest);
        }
        NtfnState_Active => {
            let mut badge2 = notification_ptr_get_ntfnMsgIdentifier(ntfnPtr);
            badge2 |= badge;
            notification_ptr_set_ntfnMsgIdentifier(ntfnPtr as *mut notification_t, badge2);
        }
        _ => panic!(
            "invalid notification state :{}",
            notification_ptr_get_state(ntfnPtr)
        ),
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

#[no_mangle]
pub fn performInvocation_Notification(ntfn: *mut notification_t, badge: usize) -> exception_t {
    sendSignal(ntfn, badge);
    exception_t::EXCEPTION_NONE
}

