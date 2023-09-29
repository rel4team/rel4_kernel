use common::utils::convert_to_mut_type_ref;

use super::tcb_t;


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct tcb_queue_t {
    pub head: usize,
    pub tail: usize,
}

impl tcb_queue_t {
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
    pub fn empty(&self) -> bool {
        return self.head == 0
    }
}
