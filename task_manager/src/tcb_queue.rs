use common::utils::convert_to_mut_type_ref;

use super::tcb_t;


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct tcb_queue_t {
    pub head: *mut tcb_t,
    pub tail: *mut tcb_t,
}

impl tcb_queue_t {
    pub fn ep_append(&mut self, tcb: &mut tcb_t) {
        if self.head as usize == 0 {
            self.head = tcb as *mut tcb_t;
        } else {
            unsafe { (*self.tail).tcbEPNext = tcb as *mut tcb_t as usize; }
        }

        tcb.tcbEPPrev = self.tail as usize;
        tcb.tcbEPNext = 0;
        self.tail = tcb as *mut tcb_t;
    }

    pub fn ep_dequeue(&mut self, tcb: &mut tcb_t) {
        if tcb.tcbEPPrev != 0 {
            convert_to_mut_type_ref::<tcb_t>(tcb.tcbEPPrev).tcbEPNext = tcb.tcbEPNext;
        } else {
            self.head = tcb.tcbEPNext as *mut tcb_t;
        }

        if tcb.tcbEPNext != 0 {
            convert_to_mut_type_ref::<tcb_t>(tcb.tcbEPNext).tcbEPPrev = tcb.tcbEPPrev;
        } else {
            self.tail = tcb.tcbEPPrev as *mut tcb_t;
        }
    }
}

#[no_mangle]
pub fn tcbEPAppend(tcb: *mut tcb_t, mut queue: tcb_queue_t) -> tcb_queue_t {
    unsafe {
        queue.ep_append(&mut *tcb);
        queue
    }
}

#[no_mangle]
pub fn tcbEPDequeue(tcb: *mut tcb_t, mut queue: tcb_queue_t) -> tcb_queue_t {
    unsafe {
        queue.ep_dequeue(&mut *tcb);
        queue
    }
}