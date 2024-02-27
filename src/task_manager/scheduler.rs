use crate::{BIT, MASK};
use crate::common::{sel4_config::*, utils::convert_to_mut_type_ref};
use core::arch::asm;
use core::intrinsics::{likely, unlikely};
use log::debug;

use crate::common::utils::convert_to_mut_type_ref_unsafe;
use super::{FaultIP, NextIP, SSTATUS, SSTATUS_SPP, SSTATUS_SPIE, sp, set_thread_state, ThreadState};

use super::{tcb::tcb_t, tcb_queue_t};

#[cfg(feature = "ENABLE_SMP")]
use crate::{
    common::utils::cpu_id,
    deps::{doMaskReschedule, ksIdleThreadTCB, kernel_stack_alloc}
};
use crate::boot::cpu_idle;

#[cfg(feature = "ENABLE_SMP")]
#[derive(Debug, Copy, Clone)]
pub struct SmpStateData {
    pub ipiReschedulePending: usize,
    pub ksReadyQueues: [tcb_queue_t; CONFIG_NUM_DOMAINS * CONFIG_NUM_PRIORITIES],
    pub ksReadyQueuesL1Bitmap: [usize; CONFIG_NUM_DOMAINS],
    pub ksReadyQueuesL2Bitmap: [[usize; L2_BITMAP_SIZE]; CONFIG_NUM_DOMAINS],
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
            ksReadyQueuesL2Bitmap: [[0; L2_BITMAP_SIZE]; CONFIG_NUM_DOMAINS],
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
pub static mut ksDebugTCBs: usize = 0;
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

// #[no_mangle]
// #[link_section = "._idle_thread"]
// pub static mut ksIdleThreadTCB: [[u8; BIT!(seL4_TCBBits)]; CONFIG_MAX_NUM_NODES] =
//     [[0; BIT!(seL4_TCBBits)]; CONFIG_MAX_NUM_NODES];

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
pub fn get_idle_thread() -> &'static mut tcb_t {
    unsafe {
        #[cfg(feature = "ENABLE_SMP")] {
            convert_to_mut_type_ref::<tcb_t>(ksSMP[cpu_id()].ksIdleThread)
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            convert_to_mut_type_ref::<tcb_t>(ksIdleThread)
        }
    }
}

#[inline]
pub fn get_ks_scheduler_action() -> usize {
    unsafe {
        #[cfg(feature = "ENABLE_SMP")] {
            ksSMP[cpu_id()].ksSchedulerAction
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            ksSchedulerAction
        }
    }
}

#[inline]
pub fn set_ks_scheduler_action(action: usize) {
    // if hart_id() == 0 {
    //     debug!("set_ks_scheduler_action: {}", action);
    // }
    unsafe {
        #[cfg(feature = "ENABLE_SMP")] {
            ksSMP[cpu_id()].ksSchedulerAction = action;
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            ksSchedulerAction = action
        }
    }
}

#[inline]
pub fn get_currenct_thread() -> &'static mut tcb_t {
    unsafe {
        #[cfg(feature = "ENABLE_SMP")] {
            convert_to_mut_type_ref::<tcb_t>(ksSMP[cpu_id()].ksCurThread)
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            convert_to_mut_type_ref::<tcb_t>(ksCurThread)
        }
    }
}

#[inline]
pub fn get_currenct_thread_unsafe() -> &'static mut tcb_t {
    unsafe {
        #[cfg(feature = "ENABLE_SMP")] {
            convert_to_mut_type_ref_unsafe::<tcb_t>(ksSMP[cpu_id()].ksCurThread)
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            convert_to_mut_type_ref_unsafe::<tcb_t>(ksCurThread)
        }
    }
}

#[inline]
pub fn set_current_scheduler_action(action: usize) {
    unsafe {
        #[cfg(feature = "ENABLE_SMP")] {
            ksSMP[cpu_id()].ksSchedulerAction = action;
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            ksSchedulerAction = action;
        }
    }
}


#[inline]
pub fn set_current_thread(thread: &tcb_t) {
    unsafe {
        #[cfg(feature = "ENABLE_SMP")] {
            ksSMP[cpu_id()].ksCurThread = thread.get_ptr();
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            ksCurThread = thread.get_ptr()
        }
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

#[cfg(not(feature = "ENABLE_SMP"))]
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

#[cfg(feature = "ENABLE_SMP")]
#[inline]
fn getHighestPrio(dom: usize) -> prio_t {
    unsafe {
        let l1index = wordBits - 1 - ksSMP[cpu_id()].ksReadyQueuesL1Bitmap[dom].leading_zeros() as usize;
        let l1index_inverted = invert_l1index(l1index);
        let l2index =
            wordBits - 1 - (ksSMP[cpu_id()].ksReadyQueuesL2Bitmap[dom])[l1index_inverted].leading_zeros() as usize;
        l1index_to_prio(l1index) | l2index
    }
}

#[inline]
pub fn isHighestPrio(dom: usize, prio: prio_t) -> bool {
    #[cfg(feature = "ENABLE_SMP")] {
        unsafe { ksSMP[cpu_id()].ksReadyQueuesL1Bitmap[dom] == 0 || prio >= getHighestPrio(dom) }
    }
    #[cfg(not(feature = "ENABLE_SMP"))] {
        unsafe { ksReadyQueuesL1Bitmap[dom] == 0 || prio >= getHighestPrio(dom) }
    }
}

#[inline]
pub fn addToBitmap(_cpu: usize, dom: usize, prio: usize) {
    unsafe {
        let l1index = prio_to_l1index(prio);
        let l1index_inverted = invert_l1index(l1index);
        #[cfg(feature = "ENABLE_SMP")] {
            ksSMP[_cpu].ksReadyQueuesL1Bitmap[dom]|= BIT!(l1index);
            ksSMP[_cpu].ksReadyQueuesL2Bitmap[dom][l1index_inverted] |= BIT!(prio & MASK!(wordRadix));
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            ksReadyQueuesL1Bitmap[dom] |= BIT!(l1index);
            ksReadyQueuesL2Bitmap[dom][l1index_inverted] |= BIT!(prio & MASK!(wordRadix));
        }
    }
}

#[inline]
pub fn removeFromBitmap(_cpu: usize, dom: usize, prio: usize) {
    unsafe {
        let l1index = prio_to_l1index(prio);
        let l1index_inverted = invert_l1index(l1index);
        #[cfg(feature = "ENABLE_SMP")] {
            ksSMP[_cpu].ksReadyQueuesL2Bitmap[dom][l1index_inverted] &= !BIT!(prio & MASK!(wordRadix));
            if unlikely(ksSMP[_cpu].ksReadyQueuesL2Bitmap[dom][l1index_inverted] == 0) {
                ksSMP[_cpu].ksReadyQueuesL1Bitmap[dom] &= !(BIT!((l1index)));
            }
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            ksReadyQueuesL2Bitmap[dom][l1index_inverted] &= !BIT!(prio & MASK!(wordRadix));
            if unlikely(ksReadyQueuesL2Bitmap[dom][l1index_inverted] == 0) {
                ksReadyQueuesL1Bitmap[dom] &= !(BIT!((l1index)));
            }
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
    // if hart_id() == 0 {
    //     debug!("scheduleChooseNewThread");
    // }

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
        let ks_l1_bit = {
            #[cfg(feature = "ENABLE_SMP")] {
                ksSMP[cpu_id()].ksReadyQueuesL1Bitmap[dom]
            }
            #[cfg(not(feature = "ENABLE_SMP"))] {
                ksReadyQueuesL1Bitmap[dom]
            }
        };
        if likely(ks_l1_bit != 0) {
            let prio = getHighestPrio(dom);
            let thread = {
                #[cfg(feature = "ENABLE_SMP")] {
                    ksSMP[cpu_id()].ksReadyQueues[ready_queues_index(dom, prio)].head
                }
                #[cfg(not(feature = "ENABLE_SMP"))] {
                    ksReadyQueues[ready_queues_index(dom, prio)].head
                }

            };
            assert_ne!(thread, 0);
            convert_to_mut_type_ref::<tcb_t>(thread).switch_to_this();
        } else {
            get_idle_thread().switch_to_this();
        }
    }
}

#[no_mangle]
pub fn rescheduleRequired() {
    if get_ks_scheduler_action() != SchedulerAction_ResumeCurrentThread
        && get_ks_scheduler_action() != SchedulerAction_ChooseNewThread
    {
        convert_to_mut_type_ref::<tcb_t>(get_ks_scheduler_action()).sched_enqueue();
    }
    // ksSchedulerAction = SchedulerAction_ChooseNewThread;
    set_ks_scheduler_action(SchedulerAction_ChooseNewThread);
}

#[no_mangle]
pub fn schedule() {
    if get_ks_scheduler_action() != SchedulerAction_ResumeCurrentThread {
        let was_runnable: bool;
        let current_tcb = get_currenct_thread();
        if current_tcb.is_runnable() {
            was_runnable = true;
            current_tcb.sched_enqueue();
        } else {
            was_runnable = false;
        }

        if get_ks_scheduler_action() == SchedulerAction_ChooseNewThread {
            scheduleChooseNewThread();
        } else {
            // let candidate = ksSchedulerAction as *mut tcb_t;
            let candidate = convert_to_mut_type_ref::<tcb_t>(get_ks_scheduler_action());
            let fastfail = get_currenct_thread().get_ptr() == get_idle_thread().get_ptr()
                || candidate.tcbPriority < get_currenct_thread().tcbPriority;
            if fastfail && !isHighestPrio(unsafe { ksCurDomain }, candidate.tcbPriority) {
                candidate.sched_enqueue();
                // ksSchedulerAction = SchedulerAction_ChooseNewThread;
                set_ks_scheduler_action(SchedulerAction_ChooseNewThread);
                scheduleChooseNewThread();
            } else if was_runnable
                && candidate.tcbPriority == get_currenct_thread().tcbPriority
            {
                candidate.sched_append();
                set_ks_scheduler_action(SchedulerAction_ChooseNewThread);
                scheduleChooseNewThread();
            } else {
                candidate.switch_to_this();
            }
        }
    }
    set_ks_scheduler_action(SchedulerAction_ResumeCurrentThread);
    unsafe {
        #[cfg(feature = "ENABLE_SMP")] {
            doMaskReschedule(ksSMP[cpu_id()].ipiReschedulePending);
            ksSMP[cpu_id()].ipiReschedulePending = 0;
        }

    }
}

#[inline]
pub fn schedule_tcb(tcb_ref: &tcb_t) {
    if tcb_ref.get_ptr() == get_currenct_thread_unsafe().get_ptr()
        && get_ks_scheduler_action() == SchedulerAction_ResumeCurrentThread
        && !tcb_ref.is_runnable()
    {
        rescheduleRequired();
    }
}

#[cfg(feature = "ENABLE_SMP")]
#[inline]
pub fn possible_switch_to(target: &mut tcb_t) {
    if unsafe { ksCurDomain != target.domain || target.tcbAffinity != cpu_id() } {
        target.sched_enqueue();
    } else if get_ks_scheduler_action() != SchedulerAction_ResumeCurrentThread {
        rescheduleRequired();
        target.sched_enqueue();
    } else {
        set_ks_scheduler_action(target.get_ptr());
    }
}

#[cfg(not(feature = "ENABLE_SMP"))]
#[inline]
pub fn possible_switch_to(target: &mut tcb_t) {
    if unsafe { ksCurDomain != target.domain } {
        target.sched_enqueue();
    } else if get_ks_scheduler_action() != SchedulerAction_ResumeCurrentThread {
        rescheduleRequired();
        target.sched_enqueue();
    } else {
        set_ks_scheduler_action(target.get_ptr());
    }
}

#[no_mangle]
pub fn timerTick() {
    let current = get_currenct_thread();
    // if hart_id() == 0 {
    //     debug!("timer tick current: {:#x}", current.get_ptr());
    // }

    if likely(current.get_state() == ThreadState::ThreadStateRunning) {
        if current.tcbTimeSlice > 1 {
            // if hart_id() == 0 {
            //     debug!("tcbTimeSlice : {}", current.tcbTimeSlice);
            // }
            current.tcbTimeSlice -= 1;
        } else {
            // if hart_id() == 0 {
            //     debug!("switch");
            // }

            current.tcbTimeSlice = CONFIG_TIME_SLICE;
            current.sched_append();
            rescheduleRequired();
        }
    }
}


#[no_mangle]
pub fn activateThread() {

    let thread = get_currenct_thread();
    // debug!("current: {:#x}", thread.get_ptr());
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
        ThreadState::ThreadStateIdleThreadState => return {

        },
        _ => panic!(
            "current thread is blocked , state id :{}",
            thread.get_state() as usize
        ),
    }
}


// #[no_mangle]
// pub static mut kernel_stack_alloc: [[u8; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES] =
//     [[0; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES];

#[cfg(not(feature = "ENABLE_SMP"))]
pub fn create_idle_thread() {
    use crate::deps::{ksIdleThreadTCB, kernel_stack_alloc};

    unsafe {
        let pptr = ksIdleThreadTCB as usize as *mut usize;
        ksIdleThread = pptr.add(TCB_OFFSET) as usize;
        // let tcb = convert_to_mut_type_ref::<tcb_t>(ksIdleThread as usize);
        let tcb = get_idle_thread();
        tcb.set_register(NextIP, idle_thread as usize);
        tcb.set_register(SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
        tcb.set_register(sp, kernel_stack_alloc as usize + BIT!(CONFIG_KERNEL_STACK_BITS));
        set_thread_state(tcb, ThreadState::ThreadStateIdleThreadState);
    }
}

#[cfg(feature = "ENABLE_SMP")]
pub fn create_idle_thread() {
    use log::debug;

    unsafe {
        for i in 0..CONFIG_MAX_NUM_NODES {
            let pptr = (ksIdleThreadTCB as usize + i * BIT!(seL4_TCBBits))as *mut usize;
            ksSMP[i].ksIdleThread = pptr.add(TCB_OFFSET) as usize;
            debug!("ksIdleThread: {:#x}", ksSMP[i].ksIdleThread);
            let tcb = convert_to_mut_type_ref::<tcb_t>(ksSMP[i].ksIdleThread);
            tcb.set_register(NextIP, idle_thread as usize);
            tcb.set_register(SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
            tcb.set_register(sp, kernel_stack_alloc as usize + (i + 1) * BIT!(CONFIG_KERNEL_STACK_BITS));
            set_thread_state(tcb, ThreadState::ThreadStateIdleThreadState);
            tcb.tcbAffinity = i;
        }
    }
}



fn idle_thread() {
    unsafe {
        loop {
            cpu_idle[cpu_id()] = true;
            asm!("wfi");
        }
    }
}