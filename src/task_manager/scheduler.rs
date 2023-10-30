use crate::{BIT, MASK};
use crate::common::{sel4_config::*, utils::convert_to_mut_type_ref};
use core::arch::asm;
use core::intrinsics::{likely, unlikely};
use crate::common::utils::hart_id;
use super::{FaultIP, NextIP, SSTATUS, SSTATUS_SPP, SSTATUS_SPIE, sp, set_thread_state, ThreadState};

use super::{tcb::tcb_t, tcb_queue_t};

#[cfg(feature = "ENABLE_SMP")]
#[derive(Debug, Copy, Clone)]
pub struct SmpStateData {
    pub ipiReschedulePending: usize,
    pub ksReadyQueues: [tcb_queue_t; CONFIG_NUM_DOMAINS * CONFIG_NUM_PRIORITIES],
    pub ksReadyQueuesL1Bitmap: [usize; CONFIG_NUM_DOMAINS],
    pub ksReadyQueuesL2Bitmap: [usize; CONFIG_NUM_DOMAINS * L2_BITMAP_SIZE],
    pub ksCurThread: usize,
    pub ksIdleThread: usize,
    pub ksSchedulerAction: usize,
    pub ksDebugTCBs: usize,
    // TODO: Cache Line 对齐

}

#[cfg(feature = "ENABLE_SMP")]
#[no_mangle]
pub static mut ksSMP: [SmpStateData; CONFIG_MAX_NUM_NODES] = [SmpStateData {
            ipiReschedulePending: 0,
            ksReadyQueues: [tcb_queue_t {head: 0, tail: 0}; CONFIG_NUM_DOMAINS * CONFIG_NUM_PRIORITIES],
            ksReadyQueuesL1Bitmap: [0; CONFIG_NUM_DOMAINS],
            ksReadyQueuesL2Bitmap: [0; CONFIG_NUM_DOMAINS * L2_BITMAP_SIZE],
            ksCurThread: 0,
            ksIdleThread: 0,
            ksSchedulerAction: 1,
            ksDebugTCBs: 0,
        }; CONFIG_MAX_NUM_NODES];


#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct dschedule_t {
    pub domain: usize,
    pub length: usize,
}

pub const SchedulerAction_ResumeCurrentThread: usize = 0;
pub const SchedulerAction_ChooseNewThread: usize = 1;
pub const ksDomScheduleLength: usize = 1;
pub const CONFIG_KERNEL_STACK_BITS: usize = 12;

#[no_mangle]
pub static mut ksDomainTime: usize = 0;

#[no_mangle]
pub static mut ksCurDomain: usize = 0;

#[no_mangle]
pub static mut ksDomScheduleIdx: usize = 0;

#[no_mangle]
pub static mut ksCurThread: usize = 0;

#[no_mangle]
pub static mut ksIdleThread: usize = 0;

#[no_mangle]
pub static mut ksSchedulerAction: usize = 1;

#[no_mangle]
pub static mut ksReadyQueues: [tcb_queue_t; NUM_READY_QUEUES] = [tcb_queue_t {
    head: 0,
    tail: 0,
}; NUM_READY_QUEUES];

#[no_mangle]
pub static mut ksReadyQueuesL2Bitmap: [[usize; L2_BITMAP_SIZE]; CONFIG_NUM_DOMAINS] =
    [[0; L2_BITMAP_SIZE]; CONFIG_NUM_DOMAINS];

#[no_mangle]
pub static mut ksReadyQueuesL1Bitmap: [usize; CONFIG_NUM_DOMAINS] = [0; CONFIG_NUM_DOMAINS];

#[no_mangle]
#[link_section = "._idle_thread"]
pub static mut ksIdleThreadTCB: [[u8; BIT!(seL4_TCBBits)]; CONFIG_MAX_NUM_NODES] =
    [[0; BIT!(seL4_TCBBits)]; CONFIG_MAX_NUM_NODES];

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut ksWorkUnitsCompleted: usize = 0;

#[link_section = ".boot.bss"]
pub static mut ksDomSchedule: [dschedule_t; ksDomScheduleLength] = [dschedule_t {
    domain: 0,
    length: 60,
}; ksDomScheduleLength];

type prio_t = usize;


#[cfg(not(feature = "ENABLE_SMP"))]
#[inline]
pub fn get_idle_thread() -> &'static mut tcb_t {
    unsafe {
        convert_to_mut_type_ref::<tcb_t>(ksIdleThread as usize)
    }
}
#[cfg(feature = "ENABLE_SMP")]
#[inline]
pub fn get_idle_thread() -> &'static mut tcb_t {
    unsafe {
        convert_to_mut_type_ref::<tcb_t>(ksSMP[hart_id()].ksIdleThread as usize)
    }
}

#[cfg(not(feature = "ENABLE_SMP"))]
#[inline]
pub fn get_currenct_thread() -> &'static mut tcb_t {
    unsafe {
        convert_to_mut_type_ref::<tcb_t>(ksCurThread as usize)
    }
}

#[cfg(feature = "ENABLE_SMP")]
#[inline]
pub fn get_currenct_thread() -> &'static mut tcb_t {
    unsafe {
        convert_to_mut_type_ref::<tcb_t>(ksSMP[hart_id()].ksCurThread as usize)
    }
}

#[cfg(not(feature = "ENABLE_SMP"))]
#[inline]
pub fn set_current_scheduler_action(action: usize) {
    unsafe { ksSchedulerAction = action; }
}


#[cfg(not(feature = "ENABLE_SMP"))]
#[inline]
pub fn set_current_thread(thread: &tcb_t) {
    unsafe { ksCurThread = thread.get_ptr() }
}

#[cfg(feature = "ENABLE_SMP")]
#[inline]
pub fn set_current_scheduler_action(action: usize) {
    unsafe {
        ksSMP[hart_id()].ksSchedulerAction = action;
    }
}

#[cfg(feature = "ENABLE_SMP")]
#[inline]
pub fn set_current_thread(thread: &tcb_t) {
    unsafe {
        ksSMP[hart_id()].ksCurThread = thread.get_ptr();
    }
}


#[inline]
pub fn get_current_domain() -> usize {
    unsafe { ksCurDomain }
}

#[inline]
pub fn ready_queues_index(dom: usize, prio: usize) -> usize {
    dom * CONFIG_NUM_PRIORITIES + prio
}

#[inline]
fn prio_to_l1index(prio: usize) -> usize {
    prio >> wordRadix
}

#[inline]
fn l1index_to_prio(l1index: usize) -> usize {
    l1index << wordRadix
}

#[inline]
fn invert_l1index(l1index: usize) -> usize {
    let inverted = L2_BITMAP_SIZE - 1 - l1index;
    inverted
}

#[inline]
fn getHighestPrio(dom: usize) -> prio_t {
    unsafe {
        let l1index = wordBits - 1 - ksReadyQueuesL1Bitmap[dom].leading_zeros() as usize;
        let l1index_inverted = invert_l1index(l1index);
        let l2index =
            wordBits - 1 - ksReadyQueuesL2Bitmap[dom][l1index_inverted].leading_zeros() as usize;
        l1index_to_prio(l1index) | l2index
    }
}

#[inline]
pub fn isHighestPrio(dom: usize, prio: prio_t) -> bool {
    unsafe { ksReadyQueuesL1Bitmap[dom] == 0 || prio >= getHighestPrio(dom) }
}

#[inline]
pub fn addToBitmap(dom: usize, prio: usize) {
    unsafe {
        let l1index = prio_to_l1index(prio);
        let l1index_inverted = invert_l1index(l1index);
        ksReadyQueuesL1Bitmap[dom] |= BIT!(l1index);
        ksReadyQueuesL2Bitmap[dom][l1index_inverted] |= BIT!(prio & MASK!(wordRadix));
    }
}

#[inline]
pub fn removeFromBitmap(dom: usize, prio: usize) {
    unsafe {
        let l1index = prio_to_l1index(prio);
        let l1index_inverted = invert_l1index(l1index);
        ksReadyQueuesL2Bitmap[dom][l1index_inverted] &= !BIT!(prio & MASK!(wordRadix));
        if unlikely(ksReadyQueuesL2Bitmap[dom][l1index_inverted] == 0) {
            ksReadyQueuesL1Bitmap[dom] &= !(BIT!((l1index)));
        }
    }
}

fn nextDomain() {
    unsafe {
        ksDomScheduleIdx += 1;
        if ksDomScheduleIdx >= ksDomScheduleLength {
            ksDomScheduleIdx = 0;
        }
        ksWorkUnitsCompleted = 0;
        ksCurDomain = ksDomSchedule[ksDomScheduleIdx].domain;
        ksDomainTime = ksDomSchedule[ksDomScheduleIdx].length;
        //FIXME ksWorkUnits not used;
        // ksWorkUnits
    }
}


fn scheduleChooseNewThread() {
    unsafe {
        if ksDomainTime == 0 {
            nextDomain();
        }
    }
    chooseThread();
}

fn chooseThread() {
    unsafe {
        let dom = 0;
        if likely(ksReadyQueuesL1Bitmap[dom] != 0) {
            let prio = getHighestPrio(dom);
            let thread = ksReadyQueues[ready_queues_index(dom, prio)].head;
            assert!(thread != 0);
            // (*thread).switch_to_this();
            convert_to_mut_type_ref::<tcb_t>(thread).switch_to_this();
        } else {
            get_idle_thread().switch_to_this();
        }
    }
}

#[no_mangle]
pub fn rescheduleRequired() {
    unsafe {
        if ksSchedulerAction as usize != SchedulerAction_ResumeCurrentThread
            && ksSchedulerAction as usize != SchedulerAction_ChooseNewThread
        {
            convert_to_mut_type_ref::<tcb_t>(ksSchedulerAction as usize).sched_enqueue();
        }
        ksSchedulerAction = SchedulerAction_ChooseNewThread;
    }
}

#[no_mangle]
pub fn schedule() {
    unsafe {
        if ksSchedulerAction as usize != SchedulerAction_ResumeCurrentThread {
            let was_runnable: bool;
            let current_tcb = get_currenct_thread();
            if current_tcb.is_runnable() {
                was_runnable = true;
                current_tcb.sched_enqueue();
            } else {
                was_runnable = false;
            }

            if ksSchedulerAction as usize == SchedulerAction_ChooseNewThread {
                scheduleChooseNewThread();
            } else {
                // let candidate = ksSchedulerAction as *mut tcb_t;
                let candidate = convert_to_mut_type_ref::<tcb_t>(ksSchedulerAction as usize);
                let fastfail = ksCurThread == ksIdleThread
                    || (*candidate).tcbPriority < (*(ksCurThread as *const tcb_t)).tcbPriority;
                if fastfail && !isHighestPrio(ksCurDomain, candidate.tcbPriority) {
                    candidate.sched_enqueue();
                    ksSchedulerAction = SchedulerAction_ChooseNewThread;
                    scheduleChooseNewThread();
                } else if was_runnable
                    && candidate.tcbPriority == (*(ksCurThread as *const tcb_t)).tcbPriority
                {
                    candidate.sched_append();
                    ksSchedulerAction = SchedulerAction_ChooseNewThread;
                    scheduleChooseNewThread();
                } else {
                    candidate.switch_to_this();
                }
            }
        }
        ksSchedulerAction = SchedulerAction_ResumeCurrentThread;
    }
}

#[inline]
pub fn schedule_tcb(tcb_ref: &tcb_t) {
    unsafe {
        if tcb_ref.get_ptr() == ksCurThread as usize
            && ksSchedulerAction as usize == SchedulerAction_ResumeCurrentThread
            && !tcb_ref.is_runnable()
        {
            rescheduleRequired();
        }
    }
}

#[inline]
pub fn possible_switch_to(target: &mut tcb_t) {
    if unsafe { ksCurDomain != target.domain } {
        target.sched_enqueue();
    } else if unsafe { ksSchedulerAction as usize != SchedulerAction_ResumeCurrentThread } {
        rescheduleRequired();
        target.sched_enqueue();
    } else {
        unsafe { ksSchedulerAction = target.get_ptr(); }
    }
}

#[no_mangle]
pub fn timerTick() {
    let current = get_currenct_thread();
    
    if likely(current.get_state() == ThreadState::ThreadStateRunning) {
        if current.tcbTimeSlice > 1 {
            current.tcbTimeSlice -= 1;
        } else {
            current.tcbTimeSlice = CONFIG_TIME_SLICE;
            current.sched_append();
            rescheduleRequired();
        }
    }
}


#[no_mangle]
pub fn activateThread() {
    unsafe {
        assert!(ksCurThread as usize != 0 && ksCurThread as usize != 1);
    }
    let thread = get_currenct_thread();
    match thread.get_state() {
        ThreadState::ThreadStateRunning => {
            return;
        }
        ThreadState::ThreadStateRestart => {
            let pc = thread.get_register(FaultIP);
            // setNextPC(thread, pc);
            thread.set_register(NextIP, pc);
            // setThreadState(thread, ThreadStateRunning);
            set_thread_state(thread, ThreadState::ThreadStateRunning);
        }
        ThreadState::ThreadStateIdleThreadState => return,
        _ => panic!(
            "current thread is blocked , state id :{}",
            thread.get_state() as usize
        ),
    }
}


#[no_mangle]
pub static mut kernel_stack_alloc: [[u8; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES] =
    [[0; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES];

#[cfg(not(feature = "ENABLE_SMP"))]
pub fn create_idle_thread() {
    unsafe {
        let pptr = ksIdleThreadTCB.as_ptr() as *mut usize;
        ksIdleThread = pptr.add(TCB_OFFSET) as usize;
        // let tcb = convert_to_mut_type_ref::<tcb_t>(ksIdleThread as usize);
        let tcb = get_idle_thread();
        tcb.set_register(NextIP, idle_thread as usize);
        tcb.set_register(SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
        tcb.set_register(sp, kernel_stack_alloc.as_ptr() as usize + BIT!(CONFIG_KERNEL_STACK_BITS));
        set_thread_state(tcb, ThreadState::ThreadStateIdleThreadState);
    }
}

#[cfg(feature = "ENABLE_SMP")]
pub fn create_idle_thread() {
    use log::debug;

    unsafe {
        for i in 0..CONFIG_MAX_NUM_NODES {
            let pptr = ksIdleThreadTCB[i].as_ptr() as *mut usize;
            ksSMP[i].ksIdleThread = pptr.add(TCB_OFFSET) as usize;
            debug!("ksIdleThread: {}", ksSMP[i].ksIdleThread);
            let tcb = convert_to_mut_type_ref::<tcb_t>(ksSMP[i].ksIdleThread);
            tcb.set_register(NextIP, idle_thread as usize);
            tcb.set_register(SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
            tcb.set_register(sp, kernel_stack_alloc.as_ptr() as usize + (i + 1) * BIT!(CONFIG_KERNEL_STACK_BITS));
            set_thread_state(tcb, ThreadState::ThreadStateIdleThreadState);
            tcb.tcbAffinity = i;
        }
    }
}

pub fn idle_thread() {
    unsafe {
        loop {
            asm!("wfi");
        }
    }
}