use crate::{
    config::badgeRegister,
    kernel::{
        boot::current_syscall_error,
        thread::{
            doNBRecvFailedTransfer,
            setMRs_syscall_error,
        },
    },
    object::notification::completeSignal,
};
use cspace::compatibility::*;
use task_manager::*;
use ipc::{*, transfer::doIPCTransfer};

use common::message_info::*;
use cspace::interface::*;

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
                    possible_switch_to(&mut *sender);
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
