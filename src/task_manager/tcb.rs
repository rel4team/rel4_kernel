use common::{structures::lookup_fault_t, MASK, utils::convert_to_mut_type_ref};
use cspace::interface::cte_t;

use crate::{structures::{notification_t, seL4_Fault_t}, config::seL4_TCBBits};

use super::{registers::n_contextRegisters, ready_queues_index, ksReadyQueues, addToBitmap, removeFromBitmap, tcb_queue_t};

use super::thread_state::*;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct arch_tcb_t {
    pub registers: [usize; n_contextRegisters],
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct tcb_t {
    pub tcbArch: arch_tcb_t,
    pub tcbState: thread_state_t,
    pub tcbBoundNotification: *mut notification_t,
    pub tcbFault: seL4_Fault_t,
    pub tcbLookupFailure: lookup_fault_t,
    pub domain: usize,
    pub tcbMCP: usize,
    pub tcbPriority: usize,
    pub tcbTimeSlice: usize,
    pub tcbFaultHandler: usize,
    pub tcbIPCBuffer: usize,
    pub tcbSchedNext: usize,
    pub tcbSchedPrev: usize,
    pub tcbEPNext: usize,
    pub tcbEPPrev: usize,
}

impl tcb_t {
    pub fn get_cspace(&mut self, i: usize) -> &'static mut cte_t {
        unsafe {
            let p = ((self as *mut tcb_t as usize) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &mut *(p.add(i))
        }
    }

    pub fn sched_enqueue(&mut self) {
        let self_ptr = self as *mut tcb_t;
        if self.tcbState.get_tcb_queued() == 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = unsafe { ksReadyQueues[idx] };
            if queue.tail as usize == 0 {
                queue.head = self_ptr;
                addToBitmap(dom, prio);
            } else {
                convert_to_mut_type_ref::<tcb_t>(queue.tail as usize).tcbSchedNext = self_ptr as usize;
            }
            self.tcbSchedPrev = queue.tail as usize;
            self.tcbSchedNext = 0;
            queue.tail = self_ptr;
            unsafe { ksReadyQueues[idx] = queue; }
            self.tcbState.set_tcb_queued(1);
        }
    }

    pub fn sched_dequeue(&mut self) {
        if self.tcbState.get_tcb_queued() != 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = unsafe { ksReadyQueues[idx] };
            if self.tcbSchedPrev != 0 {
                convert_to_mut_type_ref::<tcb_t>(self.tcbSchedPrev).tcbSchedNext = self.tcbSchedNext;
            } else {
                queue.head = self.tcbSchedNext as *mut tcb_t;
                if self.tcbSchedNext == 0 {
                    removeFromBitmap(dom, prio);
                }
            }
            if self.tcbSchedNext != 0 {
                convert_to_mut_type_ref::<tcb_t>(self.tcbSchedNext).tcbSchedPrev = self.tcbSchedPrev;
            } else {
                queue.tail = self.tcbSchedPrev as *mut tcb_t;
            }
            unsafe { ksReadyQueues[idx] = queue; }
            self.tcbState.set_tcb_queued(0);
        }
    }

    pub fn sched_append(&mut self) {
        let self_ptr = self as *mut tcb_t;
        if self.tcbState.get_tcb_queued() == 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = unsafe { ksReadyQueues[idx] };

            if queue.head as usize == 0 {
                queue.head = self_ptr;
                addToBitmap(dom, prio);
            } else {
                let next = queue.tail;
                unsafe { (*next).tcbSchedNext = self_ptr as usize };
            }
            self.tcbSchedPrev = queue.tail as usize;
            self.tcbSchedNext = 0;
            queue.tail = self_ptr;
            unsafe { ksReadyQueues[idx] = queue; }

            self.tcbState.set_tcb_queued(1);
        }
    }

}

pub fn getCSpace(ptr: usize, i: usize) -> *mut cte_t {
    getCSpaceRef(ptr, i) as *mut cte_t
}

pub fn getCSpaceRef(ptr: usize, i: usize) -> &'static mut cte_t {
    unsafe {
        let thread =&mut *( ptr as *mut tcb_t);
        thread.get_cspace(i)
    }
}


#[no_mangle]
pub fn tcbSchedEnqueue(_tcb: *mut tcb_t) {
    unsafe {
        (*_tcb).sched_enqueue();
    }
}

#[inline]
#[no_mangle]
pub fn tcbSchedDequeue(_tcb: *mut tcb_t) {
    unsafe {
        (*_tcb).sched_dequeue();
    }
}

#[no_mangle]
pub fn tcbSchedAppend(tcb: *mut tcb_t) {
    unsafe {
        (*tcb).sched_append();
    }
}