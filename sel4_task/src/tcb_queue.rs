use sel4_common::utils::convert_to_mut_type_ref;

use super::tcb::tcb_t;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
/// Structure for the tcb queue
pub struct tcb_queue_t {
    /// The head of the queue
    pub head: usize,
    /// The tail of the queue
    pub tail: usize,
}

impl tcb_queue_t {
    /// Append a tcb to the queue
    pub fn ep_append(&mut self, tcb: &mut tcb_t) {
        if self.head == 0 {
            self.head = tcb.get_ptr();
        } else {
            convert_to_mut_type_ref::<tcb_t>(self.tail).tcbEPNext = tcb.get_ptr();
        }

        tcb.tcbEPPrev = self.tail;
        tcb.tcbEPNext = 0;
        self.tail = tcb.get_ptr();
    }

    /// Dequeue a tcb from the queue
    pub fn ep_dequeue(&mut self, tcb: &mut tcb_t) {
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

    #[inline]
    /// Check if the queue is empty
    pub fn empty(&self) -> bool {
        return self.head == 0;
    }
}
