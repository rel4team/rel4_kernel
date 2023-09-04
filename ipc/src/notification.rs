use task_manager::{tcb_queue_t, tcb_t, set_thread_state, ThreadState};

pub enum NtfnState {
    Idle = 0,
    Waiting = 1,
    Active = 2,
}

pub const NtfnState_Idle: usize = NtfnState::Idle as usize;
pub const NtfnState_Waiting: usize = NtfnState::Waiting as usize;
pub const NtfnState_Active: usize = NtfnState::Active as usize;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct notification_t {
    pub words: [usize; 4],
}

impl notification_t {
    #[inline]
    pub fn get_bound_tcb(&self) -> usize {
        let mut ret: usize;
        ret = self.words[3] & 0x7fffffffffusize;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_bound_tcb(&mut self, v64: usize) {
        self.words[3] &= !0x7fffffffffusize;
        self.words[3] |= (v64 >> 0) & 0x7fffffffffusize;
    }

    #[inline]
    pub fn get_msg_identifier(&self) -> usize {
        let ret: usize;
        ret = self.words[2] & 0xffffffffffffffffusize;
        ret
    }

    #[inline]
    pub fn set_msg_identifier(&mut self, v64: usize) {
        self.words[2] &= !0xffffffffffffffffusize;
        self.words[2] |= (v64 >> 0) & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_queue_head(&self) -> usize {
        let mut ret: usize;
        ret = self.words[1] & 0x7fffffffffusize;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_queue_head(&mut self, v64: usize) {
        self.words[1] &= !0x7fffffffffusize;
        self.words[1] |= (v64 >> 0) & 0x7fffffffff;
    }

    #[inline]
    pub fn get_queue_tail(&self) -> usize {
        let mut ret: usize;
        ret = (self.words[0] & 0xfffffffffe000000usize) >> 25;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_queue_tail(&mut self, v64: usize) {
        self.words[0] &= !0xfffffffffe000000usize;
        self.words[0] |= (v64 << 25) & 0xfffffffffe000000usize;
    }

    #[inline]
    pub fn get_state(&self) -> NtfnState {
        let ret: usize;
        ret = self.words[0] & 0x3usize;
        unsafe {
            core::mem::transmute::<u8, NtfnState>(ret as u8)
        }
    }

    #[inline]
    pub fn set_state(&mut self, v64: usize) {
        self.words[0] &= !0x3usize;
        self.words[0] |= (v64 >> 0) & 0x3usize;
    }

    #[inline]
    pub fn get_queue(&self) -> tcb_queue_t {
        tcb_queue_t { head: self.get_queue_head(), tail: self.get_queue_tail() }
    }

    #[inline]
    pub fn set_queue(&mut self, queue: &tcb_queue_t) {
        self.set_queue_head(queue.head as usize);
        self.set_queue_tail(queue.tail as usize);
    }

    #[inline]
    pub fn active(&mut self, badge: usize) {
        self.set_state(NtfnState::Active as usize);
        self.set_msg_identifier(badge);
    }

    #[inline]
    pub fn cancel_signal(&mut self, tcb: &mut tcb_t) {
        let mut queue = self.get_queue();
        queue.ep_dequeue(tcb);
        self.set_queue(&queue);
        if queue.head == 0 {
            self.set_state(NtfnState::Idle as usize);
        }
        set_thread_state(tcb, ThreadState::ThreadStateInactive);
    }
}

#[inline]
pub fn notification_ptr_get_ntfnBoundTCB(notification_ptr: *const notification_t) -> usize {
    unsafe {
        (*notification_ptr).get_bound_tcb()
    }
}

#[inline]
pub fn notification_ptr_set_ntfnBoundTCB(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).set_bound_tcb(v64)
    }
}

#[inline]
pub fn notification_ptr_get_ntfnMsgIdentifier(notification_ptr: *const notification_t) -> usize {
    unsafe {
        (*notification_ptr).get_msg_identifier()
    }
}

#[inline]
pub fn notification_ptr_set_ntfnMsgIdentifier(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).set_msg_identifier(v64)
    }
}

#[inline]
pub fn notification_ptr_get_ntfnQueue_head(notification_ptr: *const notification_t) -> usize {
    unsafe {
        (*notification_ptr).get_queue_head()
    }
}

#[inline]
pub fn notification_ptr_set_ntfnQueue_head(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).set_queue_head(v64)
    }
}

#[inline]
pub fn notification_ptr_get_ntfnQueue_tail(notification_ptr: *const notification_t) -> usize {
    unsafe {
        (*notification_ptr).get_queue_tail()
    }
}

#[inline]
pub fn notification_ptr_set_ntfnQueue_tail(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).set_queue_tail(v64)
    }
}

#[inline]
pub fn notification_ptr_get_state(notification_ptr: *const notification_t) -> usize {
    unsafe {
        (*notification_ptr).get_state() as usize
    }
}

#[inline]
pub fn notification_ptr_set_state(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).set_state(v64)
    }
}

#[inline]
#[no_mangle]
pub fn ntfn_ptr_get_queue(ptr: *const notification_t) -> tcb_queue_t {
    unsafe {
        (*ptr).get_queue()
    }
}

#[inline]
pub fn ntfn_ptr_set_queue(ptr: *mut notification_t, ntfn_queue: tcb_queue_t) {
    unsafe {
        (*ptr).set_queue(&ntfn_queue)
    }
}

#[inline]
pub fn ntfn_ptr_set_active(ntfnPtr: *mut notification_t, badge: usize) {
    unsafe {
        (*ntfnPtr).active(badge)
    }
}