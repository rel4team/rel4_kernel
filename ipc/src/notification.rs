use common::{utils::{convert_to_mut_type_ref, convert_to_option_mut_type_ref}, plus_define_bitfield};
use task_manager::{tcb_queue_t, tcb_t, set_thread_state, ThreadState, rescheduleRequired};

#[derive(PartialEq, Eq)]
pub enum NtfnState {
    Idle = 0,
    Waiting = 1,
    Active = 2,
}

pub const NtfnState_Idle: usize = NtfnState::Idle as usize;
pub const NtfnState_Waiting: usize = NtfnState::Waiting as usize;
pub const NtfnState_Active: usize = NtfnState::Active as usize;

plus_define_bitfield! {
    notification_t, 4, 0, 0, 0 => {
        new, 0 => {
            bound_tcb, get_bound_tcb, set_bound_tcb, 3, 0, 39, 0, true,
            msg_identifier, get_msg_identifier, set_msg_identifier, 2, 0, 64, 0, false,
            queue_head, get_queue_head, set_queue_head, 1, 0, 39, 0, true,
            queue_tail, get_queue_tail, set_queue_tail, 0, 25, 39, 0, true,
            state, get_usize_state, set_state, 0, 0, 2, 0, false
        }
    }
}

impl notification_t {
    #[inline]
    pub fn get_state(&self) -> NtfnState {
        unsafe {
            core::mem::transmute::<u8, NtfnState>(self.get_usize_state() as u8)
        }
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

    #[inline]
    pub fn cacncel_all_signal(&mut self) {
        if self.get_state() ==  NtfnState::Waiting {
            let mut op_thread = convert_to_option_mut_type_ref::<tcb_t>(self.get_queue_head());
            self.set_state(NtfnState::Idle as usize);
            self.set_queue_head(0);
            self.set_queue_tail(0);
            while let Some(thread) =  op_thread {
                set_thread_state(thread, ThreadState::ThreadStateRestart);
                thread.sched_enqueue();
                op_thread = convert_to_option_mut_type_ref::<tcb_t>(thread.tcbEPNext);
            }
            rescheduleRequired();
        }
    }

    #[inline]
    pub fn bind_tcb(&mut self, tcb: &mut tcb_t) {
        self.set_bound_tcb(tcb.get_ptr());
    }

    #[inline]
    pub fn unbind_tcb(&mut self) {
        self.set_bound_tcb(0);
    }

    #[inline]
    pub fn safe_unbind_tcb(&mut self) {
        let tcb = self.get_bound_tcb();
        self.unbind_tcb();
        if tcb as usize != 0 {
            convert_to_mut_type_ref::<tcb_t>(tcb).unbind_notification();
        }
    }

    #[inline]
    pub fn get_ptr(&self) -> usize {
        self as *const notification_t as usize
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