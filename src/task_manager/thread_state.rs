use crate::plus_define_bitfield;

#[derive(PartialEq, PartialOrd, Debug)]
pub enum ThreadState {
    ThreadStateInactive,
    ThreadStateRunning,
    ThreadStateRestart,
    ThreadStateBlockedOnReceive,
    ThreadStateBlockedOnSend,
    ThreadStateBlockedOnReply,
    ThreadStateBlockedOnNotification,
    #[cfg(feature = "ENABLE_ASYNC_SYSCALL")]
    ThreadStateBlockedOnExecutor,
    ThreadStateIdleThreadState,
    ThreadStateExited,
}

plus_define_bitfield! {
    thread_state_t, 3, 0, 0, 0 => {
        state_new, 0 => {
            blocking_ipc_badge, get_blocking_ipc_badge, set_blocking_ipc_badge, 2, 0, 64, 0, false,
            blocking_ipc_can_grant, get_blocking_ipc_can_grant, set_blocking_ipc_can_grant, 1, 3, 1, 0, false,
            blocking_ipc_can_grant_relpy, get_blocking_ipc_can_grant_reply, set_blocking_ipc_can_grant_reply, 1, 2, 1, 0, false,
            blocking_ipc_is_call, get_blocking_ipc_is_call, set_blocking_ipc_is_call, 1, 1, 1, 0, false,
            tcb_queued, get_tcb_queued, set_tcb_queued, 1, 0, 1, 0, false,
            blocking_object, get_blocking_object, set_blocking_object, 0, 4, 35, 4, true,
            ts_type, get_ts_type, set_ts_type, 0, 0, 4, 0, false
        }
    }
}

impl thread_state_t {
    pub fn get_state(&self) -> ThreadState {
        unsafe {
            core::mem::transmute::<u8, ThreadState>(self.get_ts_type() as u8)
        }
    }
}


#[inline]
pub fn thread_state_get_blockingIPCCanGrant(thread_state_ptr: &thread_state_t) -> usize {
    thread_state_ptr.get_blocking_ipc_can_grant()
}

#[inline]
pub fn thread_state_set_blockingIPCCanGrant(thread_state_ptr: &mut thread_state_t, v64: usize) {
    thread_state_ptr.set_blocking_ipc_can_grant(v64)
}

//thread state
pub const ThreadStateRunning: usize = ThreadState::ThreadStateRunning as usize;
pub const ThreadStateBlockedOnReceive: usize = ThreadState::ThreadStateBlockedOnReceive as usize;
pub const ThreadStateBlockedOnReply: usize = ThreadState::ThreadStateBlockedOnReply as usize;