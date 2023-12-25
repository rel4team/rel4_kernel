use crate::common::utils::convert_to_mut_type_ref;

#[cfg(feature = "ENABLE_ASYNC_SYSCALL")]
use crate::syscall::CWaker;

use super::tcb::tcb_t;


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct tcb_queue_t {
    pub head: usize,
    pub tail: usize,
}

impl tcb_queue_t {
    pub fn ep_append_tcb(&mut self, tcb: &mut tcb_t) {
        if self.head == 0 {
            self.head = tcb.get_ptr();
        } else {
            convert_to_mut_type_ref::<tcb_t>(self.tail).tcbEPNext = tcb.get_ptr();
        }

        tcb.tcbEPPrev = self.tail;
        tcb.tcbEPNext = 0;
        self.tail = tcb.get_ptr();
    }

    pub fn ep_dequeue_tcb(&mut self, tcb: &mut tcb_t) {
        if tcb.tcbEPPrev != 0 {
            convert_to_mut_type_ref::<tcb_t>(tcb.tcbEPPrev).tcbEPNext = tcb.tcbEPNext;
        } else {
            self.head = tcb.tcbEPNext;
        }

        if tcb.tcbEPNext != 0 {
            convert_to_mut_type_ref::<tcb_t>(tcb.tcbEPNext).tcbEPPrev = tcb.tcbEPPrev;
        } else {
            self.tail = tcb.tcbEPPrev;
        }
    }
    #[cfg(feature = "ENABLE_ASYNC_SYSCALL")]
    pub fn ep_append_waker(&mut self, waker: &mut CWaker) {
        if self.head == 0 {
            self.head = waker.get_ptr();
        } else {
            convert_to_mut_type_ref::<CWaker>(self.tail).next = waker.get_ptr();
        }

        waker.prev = self.tail;
        waker.next = 0;
        self.tail = waker.get_ptr();
    }

    #[cfg(feature = "ENABLE_ASYNC_SYSCALL")]
    pub fn ep_dequeue_waker(&mut self, waker: &mut CWaker) {
        if waker.prev != 0 {
            convert_to_mut_type_ref::<CWaker>(waker.prev).next = waker.next;
        } else {
            self.head = waker.next;
        }

        if waker.next != 0 {
            convert_to_mut_type_ref::<CWaker>(waker.next).prev = waker.prev;
        } else {
            self.tail = waker.prev;
        }
    }



    #[inline]
    pub fn empty(&self) -> bool {
        return self.head == 0
    }
}
