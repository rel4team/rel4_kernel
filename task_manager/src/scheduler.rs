use common::{BIT, sel4_config::{wordRadix, wordBits, NUM_READY_QUEUES, L2_BITMAP_SIZE, CONFIG_NUM_DOMAINS, seL4_TCBBits,
    CONFIG_MAX_NUM_NODES, CONFIG_NUM_PRIORITIES, CONFIG_TIME_SLICE}, MASK, utils::convert_to_mut_type_ref};


use crate::{getReStartPC, setNextPC, setThreadState, ThreadStateRunning};

use super::{tcb::tcb_t, tcb_queue_t, get_idle_thread, get_currenct_thread, ThreadState};


#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct dschedule_t {
    pub domain: usize,
    pub length: usize,
}

pub const SchedulerAction_ResumeCurrentThread: usize = 0;
pub const SchedulerAction_ChooseNewThread: usize = 1;
pub const ksDomScheduleLength: usize = 1;

#[no_mangle]
pub static mut ksDomainTime: usize = 0;

#[no_mangle]
pub static mut ksCurDomain: usize = 0;

#[no_mangle]
pub static mut ksDomScheduleIdx: usize = 0;

#[no_mangle]
pub static mut ksCurThread: *mut tcb_t = 0 as *mut tcb_t;

#[no_mangle]
pub static mut ksIdleThread: *mut tcb_t = 0 as *mut tcb_t;

#[no_mangle]
pub static mut ksSchedulerAction: *mut tcb_t = 1 as *mut tcb_t;

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


#[inline]
pub fn ready_queues_index(dom: usize, prio: usize) -> usize {
    dom * CONFIG_NUM_PRIORITIES + prio
}

#[inline]
pub fn prio_to_l1index(prio: usize) -> usize {
    prio >> wordRadix
}

#[inline]
pub fn l1index_to_prio(l1index: usize) -> usize {
    l1index << wordRadix
}

#[inline]
pub fn invert_l1index(l1index: usize) -> usize {
    let inverted = L2_BITMAP_SIZE - 1 - l1index;
    inverted
}

#[inline]
pub fn getHighestPrio(dom: usize) -> prio_t {
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
        if ksReadyQueuesL2Bitmap[dom][l1index_inverted] == 0 {
            ksReadyQueuesL1Bitmap[dom] &= !(BIT!((l1index)));
        }
    }
}

#[no_mangle]
pub fn nextDomain() {
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


#[no_mangle]
pub fn scheduleChooseNewThread() {
    unsafe {
        if ksDomainTime == 0 {
            nextDomain();
        }
    }
    chooseThread();
}

#[no_mangle]
pub fn chooseThread() {
    unsafe {
        let dom = 0;
        if ksReadyQueuesL1Bitmap[dom] != 0 {
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
        ksSchedulerAction = SchedulerAction_ChooseNewThread as *mut tcb_t;
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
                    ksSchedulerAction = SchedulerAction_ChooseNewThread as *mut tcb_t;
                    scheduleChooseNewThread();
                } else if was_runnable
                    && candidate.tcbPriority == (*(ksCurThread as *const tcb_t)).tcbPriority
                {
                    candidate.sched_append();
                    ksSchedulerAction = SchedulerAction_ChooseNewThread as *mut tcb_t;
                    scheduleChooseNewThread();
                } else {
                    candidate.switch_to_this();
                }
            }
        }
        ksSchedulerAction = SchedulerAction_ResumeCurrentThread as *mut tcb_t;
    }
}


fn schedule_tcb(tcb_ref: &tcb_t) {
    unsafe {
        if tcb_ref.get_ptr() == ksCurThread as usize
            && ksSchedulerAction as usize == SchedulerAction_ResumeCurrentThread
            && !tcb_ref.is_runnable()
        {
            rescheduleRequired();
        }
    }
}
#[no_mangle]
pub fn scheduleTCB(tptr: *const tcb_t) {
    unsafe {

        schedule_tcb(&(*tptr));
    }
}


fn possible_switch_to(target: &mut tcb_t) {
    if unsafe { ksCurDomain != target.domain } {
        target.sched_enqueue();
    } else if unsafe { ksSchedulerAction as usize != SchedulerAction_ResumeCurrentThread } {
        rescheduleRequired();
        target.sched_enqueue();
    } else {
        unsafe { ksSchedulerAction = target as *mut tcb_t; }
    }
}

#[no_mangle]
pub fn possibleSwitchTo(target: *mut tcb_t) {
    unsafe {
        possible_switch_to(&mut( *target));
    }
}

#[no_mangle]
pub fn timerTick() {
    let current = get_currenct_thread();
    
    if current.get_state() == ThreadState::ThreadStateRunning {
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
            let pc = getReStartPC(thread);
            setNextPC(thread, pc);
            setThreadState(thread, ThreadStateRunning);
        }
        ThreadState::ThreadStateIdleThreadState => return,
        _ => panic!(
            "current thread is blocked , state id :{}",
            thread.get_state() as usize
        ),
    }
}
