use crate::{
    config::badgeRegister,
    kernel::thread::doNBRecvFailedTransfer,
};

use task_manager::*;
use ipc::*;
use super::endpoint::cancelIPC;

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
            let dest = queue.head;
            assert!(dest as usize != 0);
            queue = tcbEPDequeue(dest, queue);
            let temp = queue.head as usize;
            ntfn_ptr_set_queue(ntfnPtr, queue);
            if temp as usize == 0 {
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
pub fn bindNotification(tcb: *mut tcb_t, ptr: *mut notification_t) {
    notification_ptr_set_ntfnBoundTCB(ptr, tcb as usize);
    unsafe {
        (*tcb).tcbBoundNotification = ptr as *mut notification_t as usize;
    }
}

#[no_mangle]
pub fn doUnbindNotification(tcb: *mut tcb_t, ptr: *mut notification_t) {
    notification_ptr_set_ntfnBoundTCB(ptr, 0);
    unsafe {
        (*tcb).tcbBoundNotification = 0;
    }
}

#[no_mangle]
pub fn unbindMaybeNotification(ptr: *const notification_t) {
    let tcb = notification_ptr_get_ntfnBoundTCB(ptr) as *mut tcb_t;
    if tcb as usize != 0 {
        doUnbindNotification(tcb, ptr as *mut notification_t);
    }
}

#[no_mangle]
pub fn unbindNotification(tcb: *mut tcb_t) {
    unsafe {
        let ptr = (*tcb).tcbBoundNotification;
        if ptr != 0 {
            doUnbindNotification(tcb, ptr as *mut notification_t);
        }
    }
}

#[no_mangle]
pub fn cancelSignal(threadPtr: *mut tcb_t, ntfnPtr: *mut notification_t) {
    assert!(notification_ptr_get_state(ntfnPtr) == NtfnState_Waiting);
    let mut queue = ntfn_ptr_get_queue(ntfnPtr);

    queue = tcbEPDequeue(threadPtr, queue);
    let temp = queue.head;

    ntfn_ptr_set_queue(ntfnPtr, queue);
    if temp as usize == 0 {
        notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
    }
    setThreadState(threadPtr, ThreadStateInactive);
}

#[no_mangle]
pub fn performInvocation_Notification(ntfn: *mut notification_t, badge: usize) -> exception_t {
    sendSignal(ntfn, badge);
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn cancelAllSignals(ntfnPtr: *mut notification_t) {
    if notification_ptr_get_state(ntfnPtr) == NtfnState_Waiting {
        let mut thread = notification_ptr_get_ntfnQueue_head(ntfnPtr) as *mut tcb_t;
        notification_ptr_set_state(ntfnPtr, NtfnState_Idle);
        notification_ptr_set_ntfnQueue_head(ntfnPtr, 0);
        notification_ptr_set_ntfnQueue_tail(ntfnPtr, 0);

        while thread as usize != 0 {
            setThreadState(thread, ThreadStateRestart);
            tcbSchedEnqueue(thread);
            unsafe {
                thread = (*thread).tcbEPNext as *mut tcb_t;
            }
        }
        rescheduleRequired();
    }
}
