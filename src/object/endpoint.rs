use crate::{
    config::{
        badgeRegister, msgInfoRegister, EPState_Idle, EPState_Recv, EPState_Send,
    },
    kernel::{
        boot::current_syscall_error,
        thread::{
            doIPCTransfer, doNBRecvFailedTransfer,
            setMRs_syscall_error,
        },
        transfermsg::{seL4_MessageInfo_new, wordFromMessageInfo},
        vspace::lookupIPCBuffer,
    },
    object::{
        notification::completeSignal,
        tcb::setupCallerCap,
    },
};

use task_manager::*;
use ipc::*;
use super::notification::cancelSignal;

use common::{structures::{exception_t, seL4_Fault_NullFault_new}, sel4_config::tcbReply};
use cspace::interface::*;

#[inline]
pub fn ep_ptr_set_queue(epptr: *const endpoint_t, queue: tcb_queue_t) {
    endpoint_ptr_set_epQueue_head(epptr as *mut endpoint_t, queue.head as usize);
    endpoint_ptr_set_epQueue_tail(epptr as *mut endpoint_t, queue.tail as usize);
}

#[inline]
pub fn ep_ptr_get_queue(epptr: *const endpoint_t) -> tcb_queue_t {
    let queue = tcb_queue_t {
        head: endpoint_ptr_get_epQueue_head(epptr as *mut endpoint_t) as *mut tcb_t,
        tail: endpoint_ptr_get_epQueue_tail(epptr as *mut endpoint_t) as *mut tcb_t,
    };

    queue
}

#[no_mangle]
pub fn sendIPC(
    blocking: bool,
    do_call: bool,
    badge: usize,
    canGrant: bool,
    canGrantReply: bool,
    thread: *mut tcb_t,
    epptr: *mut endpoint_t,
) {
    unsafe {
        match endpoint_ptr_get_state(epptr) {
            EPState_Idle | EPState_Send => {
                if blocking {
                    thread_state_set_tsType(&mut (*thread).tcbState, ThreadStateBlockedOnSend);
                    thread_state_set_blockingObject(&mut (*thread).tcbState, epptr as usize);
                    thread_state_set_blockingIPCCanGrant(
                        &mut (*thread).tcbState,
                        canGrant as usize,
                    );
                    thread_state_set_blockingIPCBadge(&mut (*thread).tcbState, badge);
                    thread_state_set_blockingIPCCanGrantReply(
                        &mut (*thread).tcbState,
                        canGrantReply as usize,
                    );
                    thread_state_set_blockingIPCIsCall(&mut (*thread).tcbState, do_call as usize);

                    scheduleTCB(thread);

                    let mut queue = ep_ptr_get_queue(epptr);
                    queue = tcbEPAppend(thread, queue);
                    endpoint_ptr_set_state(epptr, EPState_Send);
                    ep_ptr_set_queue(epptr, queue);
                }
            }
            EPState_Recv => {
                let mut queue = ep_ptr_get_queue(epptr);
                let dest = queue.head as *mut tcb_t;
                assert!(dest as usize != 0);

                queue = tcbEPDequeue(dest, queue);
                let temp = queue.head as usize;
                ep_ptr_set_queue(epptr, queue);

                if temp == 0 {
                    endpoint_ptr_set_state(epptr, EPState_Idle);
                }
                doIPCTransfer(thread, epptr, badge, canGrant, dest);
                let replyCanGrant = if thread_state_get_blockingIPCCanGrant(&(*dest).tcbState) != 0
                {
                    true
                } else {
                    false
                };
                setThreadState(dest, ThreadStateRunning);
                possibleSwitchTo(dest);
                if do_call {
                    if canGrant || canGrantReply {
                        setupCallerCap(thread, dest, replyCanGrant);
                    } else {
                        setThreadState(thread, ThreadStateInactive);
                    }
                }
            }
            _ => {
                panic!(
                    "unknown epptr state in sendIPC(): {}",
                    endpoint_ptr_get_state(epptr)
                );
            }
        }
    }
}

#[no_mangle]
pub fn receiveIPC(thread: *mut tcb_t, cap: &cap_t, isBlocking: bool) {
    unsafe {
        assert!(cap_get_capType(cap) == cap_endpoint_cap);
        let epptr = cap_endpoint_cap_get_capEPPtr(cap) as *const endpoint_t;
        let ntfnPtr = (*thread).tcbBoundNotification as *mut notification_t;
        if ntfnPtr as usize != 0 && notification_ptr_get_state(ntfnPtr) == NtfnState_Active {
            completeSignal(ntfnPtr, thread);
            return;
        }
        match endpoint_ptr_get_state(epptr) {
            EPState_Idle | EPState_Recv => {
                if isBlocking {
                    thread_state_set_tsType(&mut (*thread).tcbState, ThreadStateBlockedOnReceive);
                    thread_state_set_blockingObject(&mut (*thread).tcbState, epptr as usize);
                    thread_state_set_blockingIPCCanGrant(
                        &mut (*thread).tcbState,
                        cap_endpoint_cap_get_capCanGrant(cap),
                    );
                    scheduleTCB(thread);

                    let mut queue = ep_ptr_get_queue(epptr);
                    queue = tcbEPAppend(thread, queue);
                    endpoint_ptr_set_state(epptr as *mut endpoint_t, EPState_Recv);
                    ep_ptr_set_queue(epptr, queue);
                } else {
                    doNBRecvFailedTransfer(thread);
                }
            }
            EPState_Send => {
                let mut queue = ep_ptr_get_queue(epptr);

                assert!(queue.head as usize != 0);
                let sender = queue.head as *mut tcb_t;

                queue = tcbEPDequeue(sender, queue);
                let temp = queue.head as usize;
                ep_ptr_set_queue(epptr, queue);
                if temp as usize == 0 {
                    endpoint_ptr_set_state(epptr as *mut endpoint_t, EPState_Idle);
                }

                let badge = thread_state_get_blockingIPCBadge(&(*sender).tcbState);
                let canGrant = if thread_state_get_blockingIPCCanGrant(&(*sender).tcbState) != 0 {
                    true
                } else {
                    false
                };
                let canGrantReply =
                    if thread_state_get_blockingIPCCanGrantReply(&(*sender).tcbState) != 0 {
                        true
                    } else {
                        false
                    };
                // debug!("in recvIPC ,  sender:{:#x} , thread:{:#x}",sender as usize,thread as usize);
                doIPCTransfer(sender, epptr as *mut endpoint_t, badge, canGrant, thread);
                let do_call = if thread_state_get_blockingIPCIsCall(&(*sender).tcbState) != 0 {
                    true
                } else {
                    false
                };
                if do_call {
                    if canGrant || canGrantReply {
                        let grant = if cap_endpoint_cap_get_capCanGrant(cap) != 0 {
                            true
                        } else {
                            false
                        };
                        setupCallerCap(sender, thread, grant);
                    } else {
                        setThreadState(sender, ThreadStateInactive);
                    }
                } else {
                    setThreadState(sender, ThreadStateRunning);
                    possibleSwitchTo(sender);
                }
            }
            _ => {
                panic!(
                    "unknown epptr state in receiveIPC(): {}",
                    endpoint_ptr_get_state(epptr)
                );
            }
        }
    }
}

#[no_mangle]
pub fn cancelBadgedSends(epptr: *mut endpoint_t, badge: usize) {
    unsafe {
        match endpoint_ptr_get_state(epptr) {
            EPState_Idle | EPState_Recv => {}
            EPState_Send => {
                let mut queue = ep_ptr_get_queue(epptr);
                endpoint_ptr_set_state(epptr, EPState_Idle);
                endpoint_ptr_set_epQueue_head(epptr, 0);
                endpoint_ptr_set_epQueue_tail(epptr, 0);
                let mut thread = queue.head;
                while thread as usize != 0 {
                    let ptr = thread as *mut tcb_t;
                    thread = (*ptr).tcbEPNext as *mut tcb_t;
                    let b = thread_state_get_blockingIPCBadge(&(*ptr).tcbState);

                    if b == badge {
                        setThreadState(ptr, ThreadStateRestart);
                        tcbSchedEnqueue(ptr);
                        queue = tcbEPDequeue(ptr, queue);
                    }
                }

                ep_ptr_set_queue(epptr, queue);

                if queue.head as usize != 0 {
                    endpoint_ptr_set_state(epptr, EPState_Send);
                }
                rescheduleRequired();
            }
            _ => {
                panic!(
                    " unknown endpoint state in cancelBadgedSends:{}",
                    endpoint_ptr_get_state(epptr)
                );
            }
        }
    }
}

#[no_mangle]
pub fn replyFromKernel_error(thread: *mut tcb_t) {
    let ipcBuffer = lookupIPCBuffer(true, thread) as *mut usize;
    setRegister(thread, badgeRegister, 0);
    let len = setMRs_syscall_error(thread, ipcBuffer);
    unsafe {
        setRegister(
            thread,
            msgInfoRegister,
            wordFromMessageInfo(seL4_MessageInfo_new(current_syscall_error._type, 0, 0, len)),
        );
    }
}

#[no_mangle]
pub fn replyFromKernel_success_empty(thread: *mut tcb_t) {
    setRegister(thread, badgeRegister, 0);
    setRegister(
        thread,
        msgInfoRegister,
        wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, 0)),
    );
}

#[no_mangle]
pub fn cancelIPC(tptr: *mut tcb_t) {
    let state = unsafe { &(*tptr).tcbState };
    match thread_state_get_tsType(state) {
        ThreadStateBlockedOnSend | ThreadStateBlockedOnReceive => {
            let epptr = thread_state_get_blockingObject(state) as *mut endpoint_t;

            assert!(endpoint_ptr_get_state(epptr) != EPState_Idle);
            let mut queue = ep_ptr_get_queue(epptr);
            queue = tcbEPDequeue(tptr as *mut tcb_t, queue);

            let temp = queue.head as usize;

            ep_ptr_set_queue(epptr, queue);

            if temp == 0 {
                endpoint_ptr_set_state(epptr, EPState_Idle);
            }
            setThreadState(tptr, ThreadStateInactive);
        }
        ThreadStateBlockedOnNotification => {
            let ntfnPtr = thread_state_get_blockingObject(state) as *mut notification_t;
            cancelSignal(tptr, ntfnPtr);
        }
        ThreadStateBlockedOnReply => unsafe {
            (*tptr).tcbFault = seL4_Fault_NullFault_new();

            let slot = getCSpace(tptr as usize, tcbReply);
            let callerCap = mdb_node_get_mdbNext(&(*slot).cteMDBNode) as *mut cte_t;
            if callerCap as usize != 0 {
                cteDeleteOne(callerCap);
            }
        },

        _ => {}
    }
}

#[no_mangle]
pub fn cancelAllIPC(epptr: *mut endpoint_t) {
    unsafe {
        match endpoint_ptr_get_state(epptr) {
            EPState_Idle => {}
            _ => {
                let mut thread = endpoint_ptr_get_epQueue_head(epptr) as *mut tcb_t;
                endpoint_ptr_set_state(epptr, EPState_Idle);
                endpoint_ptr_set_epQueue_head(epptr, 0);
                endpoint_ptr_set_epQueue_tail(epptr, 0);
                while thread as usize != 0 {
                    let ptr = thread as *const tcb_t;
                    setThreadState(ptr as *mut tcb_t, ThreadStateRestart);
                    tcbSchedEnqueue(ptr as *mut tcb_t);
                    thread = (*ptr).tcbEPNext as *mut tcb_t;
                }
                rescheduleRequired();
            }
        }
    }
}

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
