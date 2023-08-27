#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct thread_state_t {
    pub words: [usize; 3],
}

#[derive(PartialEq, PartialOrd)]
pub enum ThreadState {
    ThreadStateInactive = 0,
    ThreadStateRunning = 1,
    ThreadStateRestart = 2,
    ThreadStateBlockedOnReceive = 3,
    ThreadStateBlockedOnSend = 4,
    ThreadStateBlockedOnReply = 5,
    ThreadStateBlockedOnNotification = 6,
    ThreadStateIdleThreadState = 7,
    ThreadStateExited = 8,
}

impl thread_state_t {
    #[inline]
    pub fn state_new() -> Self {
        let state = thread_state_t { words: [0; 3] };
        state
    }

    #[inline]
    pub fn get_blocking_ipc_badge(&self) -> usize {
        let mut ret = self.words[2] & 0xffffffffffffffffusize;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_blocking_ipc_badge(&mut self, v64: usize) {
        self.words[2] &= !0xffffffffffffffffusize;
        self.words[2] |= v64 & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_blocking_ipc_can_grant(&self) -> usize {
        let ret = (self.words[1] & 0x8usize) >> 3;
        ret
    }

    #[inline]
    pub fn set_blocking_ipc_can_grant(&mut self, v64: usize) {
        self.words[1] &= !0x8usize;
        self.words[1] |= (v64 << 3) & 0x8usize;
    }

    #[inline]
    pub fn get_blocking_ipc_can_grant_relpy(&self) -> usize {
        let ret = (self.words[1] & 0x4usize) >> 2;
        ret
    }

    #[inline]
    pub fn set_blocking_ipc_can_grant_reply(&mut self, v64: usize) {
        self.words[1] &= !0x4usize;
        self.words[1] |= (v64 << 2) & 0x4usize;
    }

    #[inline]
    pub fn get_blocking_ipc_is_call(&self) -> usize {
        let ret = (self.words[1] & 0x2usize) >> 1;
        ret
    }

    #[inline]
    pub fn set_blocking_ipc_is_call(&mut self, v64: usize) {
        self.words[1] &= !0x2usize;
        self.words[1] |= (v64 << 1) & 0x2usize;
    }

    #[inline]
    pub fn get_tcb_queued(&self) -> usize {
        let ret = (self.words[1] & 0x1usize) >> 0;
        ret
    }

    #[inline]
    pub fn set_tcb_queued(&mut self, v64: usize) {
        self.words[1] &= !0x1usize;
        self.words[1] |= (v64 << 0) & 0x1usize;
    }

    #[inline]
    pub fn get_blocking_object(&self) -> usize {
        let mut ret = (self.words[0] & 0x7ffffffff0usize) << 0;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_blocking_object(&mut self, v64: usize) {
        self.words[0] &= !0x7ffffffff0usize;
        self.words[0] |= (v64 >> 0) & 0x7ffffffff0usize;
    }

    #[inline]
    pub fn get_ts_type(&self) -> usize {
        let ret = self.words[0] & 0xfusize;
        ret
    }

    #[inline]
    pub fn set_ts_type(&mut self, v64: usize) {
        self.words[0] &= !0xfusize;
        self.words[0] |= v64 & 0xfusize;
    }
}

#[inline]
pub fn thread_state_get_blockingObject(thread_state_ptr: &thread_state_t) -> usize {
    thread_state_ptr.get_blocking_object()
}

#[inline]
pub fn thread_state_set_blockingObject(thread_state_ptr: &mut thread_state_t, v64: usize) {
    thread_state_ptr.set_blocking_object(v64)
}

#[inline]
pub fn thread_state_get_tsType(thread_state_ptr: &thread_state_t) -> usize {
    thread_state_ptr.get_ts_type()
}

#[inline]
#[no_mangle]
pub fn thread_state_set_tsType(thread_state_ptr: &mut thread_state_t, v64: usize) {
    thread_state_ptr.set_ts_type(v64)
}

#[inline]
pub fn thread_state_get_blockingIPCIsCall(thread_state_ptr: &thread_state_t) -> usize {
    thread_state_ptr.get_blocking_ipc_is_call()
}

#[inline]
pub fn thread_state_set_blockingIPCIsCall(thread_state_ptr: &mut thread_state_t, v64: usize) {
    thread_state_ptr.set_blocking_ipc_is_call(v64)
}

#[inline]
pub fn thread_state_get_tcbQueued(thread_state_ptr: &thread_state_t) -> usize {
    thread_state_ptr.get_tcb_queued()
}

#[inline]
pub fn thread_state_set_tcbQueued(thread_state_ptr: &mut thread_state_t, v64: usize) {
    thread_state_ptr.set_tcb_queued(v64)
}

#[inline]
pub fn thread_state_new() -> thread_state_t {
    thread_state_t::state_new()
}

#[inline]
pub fn thread_state_get_blockingIPCBadge(thread_state_ptr: &thread_state_t) -> usize {
    thread_state_ptr.get_blocking_ipc_badge()
}

#[inline]
pub fn thread_state_set_blockingIPCBadge(thread_state_ptr: &mut thread_state_t, v64: usize) {
    thread_state_ptr.set_blocking_ipc_badge(v64)
}

#[inline]
pub fn thread_state_get_blockingIPCCanGrant(thread_state_ptr: &thread_state_t) -> usize {
    thread_state_ptr.get_blocking_ipc_can_grant()
}

#[inline]
pub fn thread_state_set_blockingIPCCanGrant(thread_state_ptr: &mut thread_state_t, v64: usize) {
    thread_state_ptr.set_blocking_ipc_can_grant(v64)
}

#[inline]
pub fn thread_state_get_blockingIPCCanGrantReply(thread_state_ptr: &thread_state_t) -> usize {
    thread_state_ptr.get_blocking_ipc_can_grant_relpy()
}

#[inline]
pub fn thread_state_set_blockingIPCCanGrantReply(
    thread_state_ptr: &mut thread_state_t,
    v64: usize,
) {
    thread_state_ptr.set_blocking_ipc_can_grant_reply(v64)
}

//thread state
pub const ThreadStateInactive: usize = ThreadState::ThreadStateInactive as usize;
pub const ThreadStateRunning: usize = ThreadState::ThreadStateRunning as usize;
pub const ThreadStateRestart: usize = ThreadState::ThreadStateRestart as usize;
pub const ThreadStateBlockedOnReceive: usize = ThreadState::ThreadStateBlockedOnReceive as usize;
pub const ThreadStateBlockedOnSend: usize = ThreadState::ThreadStateBlockedOnSend as usize;
pub const ThreadStateBlockedOnReply: usize = ThreadState::ThreadStateBlockedOnReply as usize;
pub const ThreadStateBlockedOnNotification: usize = ThreadState::ThreadStateBlockedOnNotification as usize;
pub const ThreadStateIdleThreadState: usize = ThreadState::ThreadStateIdleThreadState as usize;
pub const ThreadStateExited: usize = ThreadState::ThreadStateExited as usize;