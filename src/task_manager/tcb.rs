use common::{structures::lookup_fault_t, MASK, utils::convert_to_mut_type_ref};
use cspace::interface::cte_t;
use vspace::{set_vm_root, pptr_t};

use crate::{structures::{notification_t, seL4_Fault_t}, config::{seL4_TCBBits, tcbVTable}};

use super::{registers::n_contextRegisters, ready_queues_index, ksReadyQueues, addToBitmap, removeFromBitmap, NextIP, FaultIP, ksIdleThread, ksCurThread,
    rescheduleRequired, possibleSwitchTo, scheduleTCB};

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
    #[inline]
    pub fn get_cspace(&self, i: usize) -> &'static cte_t {
        unsafe {
            let p = ((self as *const tcb_t as usize) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &*(p.add(i))
        }
    }

    pub fn get_cspace_mut_ref(&mut self, i: usize) -> &'static mut cte_t {
        unsafe {
            let p = ((self as *mut tcb_t as usize) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &mut *(p.add(i))
        }
    }

    #[inline]
    pub fn get_state(&self) -> ThreadState {
        unsafe { core::mem::transmute::<u8, ThreadState>(self.tcbState.get_ts_type() as u8) }
    }

    #[inline]
    pub fn is_stopped(&self) -> bool {
        match self.get_state() {

            ThreadState::ThreadStateInactive | ThreadState::ThreadStateBlockedOnNotification | ThreadState::ThreadStateBlockedOnReceive
            | ThreadState::ThreadStateBlockedOnReply | ThreadState::ThreadStateBlockedOnSend => true,

            _ => false
        }
    }

    #[inline]
    pub fn is_runnable(&self) -> bool {
        match self.get_state() {
            ThreadState::ThreadStateRunning | ThreadState::ThreadStateRestart   => true,
            _                                                                   => false,
        }
    }

    #[inline]
    pub fn set_register(&mut self, reg: usize, w: usize) {
        self.tcbArch.registers[reg] = w;
    }

    #[inline]
    pub fn get_register(&self, reg: usize) -> usize {
        self.tcbArch.registers[reg]
    }
    
    #[inline]
    pub fn set_mcp_priority(&mut self, mcp: usize) {
        self.tcbMCP = mcp;
    }

    #[inline]
    pub fn set_priority(&mut self, priority: usize) {
        // tcbSchedDequeue(tptr);
        self.sched_dequeue();
        self.tcbPriority = priority;
        if self.is_runnable() {
            if self.get_ptr() == unsafe { ksCurThread as usize } {
                rescheduleRequired();
            } else {
                possibleSwitchTo(self as *mut tcb_t);
            }
        }
    }

    #[inline]
    pub fn set_domain(&mut self, dom: usize) {
        self.sched_dequeue();
        self.domain = dom;
        if self.is_runnable() {
            self.sched_enqueue();
        }

        if self.get_ptr() == unsafe { ksCurThread as usize } {
            rescheduleRequired();
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

    pub fn set_vm_root(&self) -> Result<(), lookup_fault_t> {
        // let threadRoot = &(*getCSpace(thread as usize, tcbVTable)).cap;
        let thread_root = self.get_cspace(tcbVTable).cap;
        set_vm_root(&thread_root)
    }

    #[inline]
    pub fn switch_to_this(&mut self) {
        let _ = self.set_vm_root();
        self.sched_dequeue();
        unsafe {
            ksCurThread = self as *mut tcb_t;
        }
    }

    pub fn get_ptr(&self) -> pptr_t {
        self as *const tcb_t as usize
    }

}

#[inline]
pub fn get_idle_thread() -> &'static mut tcb_t {
    unsafe {
        convert_to_mut_type_ref::<tcb_t>(ksIdleThread as usize)
    }
}

#[inline]
pub fn get_currenct_thread() -> &'static mut tcb_t {
    unsafe {
        convert_to_mut_type_ref::<tcb_t>(ksCurThread as usize)
    }
}


pub fn getCSpace(ptr: usize, i: usize) -> *mut cte_t {
    getCSpaceMutRef(ptr, i) as *mut cte_t
}


pub fn getCSpaceRef(ptr: usize, i: usize) -> &'static cte_t {
    unsafe {
        let thread =&mut *( ptr as *mut tcb_t);
        thread.get_cspace(i)
    }
}

pub fn getCSpaceMutRef(ptr: usize, i: usize) -> &'static mut cte_t {
    unsafe {
        let thread =&mut *( ptr as *mut tcb_t);
        thread.get_cspace_mut_ref(i)
    }
}


#[no_mangle]
pub fn tcbSchedEnqueue(_tcb: *mut tcb_t) {
    unsafe {
        (*_tcb).sched_enqueue();
    }
}

#[inline]
pub fn tcbSchedDequeue(_tcb: *mut tcb_t) {
    unsafe {
        (*_tcb).sched_dequeue();
    }
}

pub fn tcbSchedAppend(tcb: *mut tcb_t) {
    unsafe {
        (*tcb).sched_append();
    }
}

#[inline]
pub fn isStopped(thread: *const tcb_t) -> bool {
    if thread as usize == 0 || thread as usize == 1 {
        return true;
    }
    unsafe {
        (*thread).is_stopped()
    }
}

#[inline]
pub fn isRunnable(thread: *const tcb_t) -> bool {
    if thread as usize == 0 || thread as usize == 1 {
        return false;
    }
    unsafe {
        (*thread).is_runnable()
    }
}

#[inline]
pub fn setRegister(thread: *mut tcb_t, reg: usize, w: usize) {
    unsafe {
        (*thread).set_register(reg, w)
    }
}

#[inline]
pub fn getRegister(thread: *const tcb_t, reg: usize) -> usize {
    unsafe {
        (*thread).get_register(reg)
     }
}

#[no_mangle]
pub fn setThreadState(tptr: *mut tcb_t, ts: usize) {
    unsafe {
        thread_state_set_tsType(&mut (*tptr).tcbState, ts);
        scheduleTCB(tptr);
    }
}


pub fn getReStartPC(thread: *const tcb_t) -> usize {
    getRegister(thread, FaultIP)
}

#[inline]
pub fn setRestartPC(thread: *mut tcb_t, v: usize) {
    setRegister(thread, NextIP, v);
}

#[inline]
pub fn setNextPC(thread: *mut tcb_t, v: usize) {
    setRegister(thread, NextIP, v);
}

#[inline]
pub fn updateReStartPC(tcb: *mut tcb_t) {
    setRegister(tcb, FaultIP, getRegister(tcb, NextIP));
}

pub fn setVMRoot(thread: *mut tcb_t) -> Result<(), lookup_fault_t> {
    unsafe {
        (*thread).set_vm_root()
    }
}


pub fn switchToThread(thread: *mut tcb_t) {
    unsafe {
        (*thread).switch_to_this()
    }
}

pub fn setMCPriority(tptr: *mut tcb_t, mcp: usize) {
    unsafe {
        (*tptr).set_mcp_priority(mcp)
    }
}

pub fn setPriority(tptr: *mut tcb_t, prio: usize) {
    unsafe {
       (*tptr).set_priority(prio);
    }
}

#[no_mangle]
pub fn setDomain(tptr: *mut tcb_t, _dom: usize) {
    unsafe {
        (*tptr).set_domain(_dom)
    }
}