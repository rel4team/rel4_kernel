use crate::{
    config::{
        ksDomScheduleLength, msgInfoRegister, msgRegister, n_msgRegisters, seL4_AlignmentError,
        seL4_DeleteFirst, seL4_FailedLookup, seL4_Fault_NullFault, seL4_IllegalOperation,
        seL4_InvalidArgument, seL4_InvalidCapability, seL4_MsgMaxExtraCaps, seL4_MsgMaxLength,
        seL4_NotEnoughMemory, seL4_RangeError, seL4_RevokeFirst, seL4_TCBBits,
        seL4_TruncatedMessage, DomainSetSet, SchedulerAction_ChooseNewThread,
        SchedulerAction_ResumeCurrentThread, ThreadStateBlockedOnNotification,
        ThreadStateBlockedOnReceive, ThreadStateBlockedOnReply, ThreadStateBlockedOnSend,
        ThreadStateIdleThreadState, ThreadStateInactive, ThreadStateRestart, ThreadStateRunning,
        CONFIG_KERNEL_STACK_BITS, CONFIG_MAX_NUM_NODES, CONFIG_NUM_DOMAINS, L2_BITMAP_SIZE,
        NUM_READY_QUEUES, SSTATUS_SPIE, SSTATUS_SPP,
    },
    object::{
        cap::{cteDeleteOne, cteInsert},
        cnode::setupReplyMaster,
        endpoint::cancelIPC,
        objecttype::{cap_endpoint_cap, cap_get_capType, cap_null_cap, cap_thread_cap, deriveCap},
        structure_gen::{
            cap_endpoint_cap_get_capEPBadge, cap_endpoint_cap_get_capEPPtr,
            cap_thread_cap_get_capTCBPtr, seL4_Fault_get_seL4_FaultType, thread_state_get_tsType,
            thread_state_set_tsType,
        },
        tcb::{
            copyMRs, getHighestPrio, isHighestPrio, lookupExtraCaps, ready_queues_index,
            tcbSchedAppend, tcbSchedDequeue, tcbSchedEnqueue,
        },
    },
    println,
    structures::{
        arch_tcb_t, cap_transfer_t, cte_t, endpoint_t, exception_t, seL4_MessageInfo_t,
        tcb_queue_t, tcb_t,
    },
    syscall::getSyscallArg,
    BIT, MASK,
};

use core::{
    arch::asm,
    intrinsics::{likely, unlikely},
};

use super::{
    boot::{
        current_extra_caps, current_lookup_fault, current_syscall_error, ksDomSchedule,
        ksWorkUnitsCompleted,
    },
    cspace::{lookupCap, rust_lookupTargetSlot},
    fault::{handleFaultReply, setMRs_fault, setMRs_lookup_failure},
    transfermsg::{
        capTransferFromWords, messageInfoFromWord, seL4_MessageInfo_new,
        seL4_MessageInfo_ptr_get_capsUnwrapped, seL4_MessageInfo_ptr_get_length,
        seL4_MessageInfo_ptr_set_capsUnwrapped, seL4_MessageInfo_ptr_set_extraCaps,
        seL4_MessageInfo_ptr_set_length, wordFromMEssageInfo,
    },
    vspace::{lookupIPCBuffer, setVMRoot},
};

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
pub static mut kernel_stack_alloc: [[u8; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES] =
    [[0; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES];

#[no_mangle]
pub static mut ksReadyQueues: [tcb_queue_t; NUM_READY_QUEUES] = [tcb_queue_t {
    head: 0 as *mut tcb_t,
    tail: 0 as *mut tcb_t,
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

type prio_t = usize;
pub const ra: usize = 0;
pub const sp: usize = 1;
const gp: usize = 2;
const tp: usize = 3;
pub const TLS_BASE: usize = 3;
const t0: usize = 4;
const t1: usize = 5;
const t2: usize = 6;
const s0: usize = 7;
const s1: usize = 8;
const a0: usize = 9;
pub const capRegister: usize = 9;
pub const badgeRegister: usize = 9;
const a1: usize = 10;
const a2: usize = 11;
const a3: usize = 12;
const a4: usize = 13;
const a5: usize = 14;
const a6: usize = 15;
const a7: usize = 16;
const s2: usize = 17;
const s3: usize = 18;
const s4: usize = 19;
const s5: usize = 20;
const s6: usize = 21;
const s7: usize = 22;
const s8: usize = 23;
const s9: usize = 24;
const s10: usize = 25;
const s11: usize = 26;
const t3: usize = 27;
const t4: usize = 28;
const t5: usize = 29;
const t6: usize = 30;
pub const SCAUSE: usize = 31;
pub const SSTATUS: usize = 32;
pub const FaultIP: usize = 33;
pub const NextIP: usize = 34;
pub const n_contextRegisters: usize = 35;

#[inline]
pub fn isStopped(thread: *const tcb_t) -> bool {
    if thread as usize == 0 || thread as usize == 1 {
        return true;
    }
    unsafe {
        match thread_state_get_tsType(&(*thread).tcbState) {
            ThreadStateInactive => true,
            ThreadStateBlockedOnNotification => true,
            ThreadStateBlockedOnReceive => true,
            ThreadStateBlockedOnReply => true,
            ThreadStateBlockedOnSend => true,
            _ => false,
        }
    }
}

#[inline]
pub fn isRunnable(thread: *const tcb_t) -> bool {
    if thread as usize == 0 || thread as usize == 1 {
        return false;
    }
    unsafe {
        match thread_state_get_tsType(&(*thread).tcbState) {
            ThreadStateRunning => true,
            ThreadStateRestart => true,
            _ => false,
        }
    }
}

#[inline]
pub fn setRegister(thread: *mut tcb_t, reg: usize, w: usize) {
    unsafe {
        (*thread).tcbArch.registers[reg] = w;
    }
}

#[inline]
pub fn getRegister(thread: *const tcb_t, reg: usize) -> usize {
    unsafe { (*thread).tcbArch.registers[reg] }
}

pub fn idle_thread() {
    unsafe {
        while true {
            asm!("wfi");
        }
    }
}

#[no_mangle]
pub fn setMR(receiver: *mut tcb_t, receivedBuffer: *mut usize, offset: usize, reg: usize) -> usize {
    if offset >= n_msgRegisters {
        if receivedBuffer as usize != 0 {
            let ptr = unsafe { receivedBuffer.add(offset + 1) };
            unsafe {
                *ptr = reg;
            }
            return offset + 1;
        } else {
            return n_msgRegisters;
        }
    } else {
        setRegister(receiver, msgRegister[offset], reg);
        return offset + 1;
    }
}

#[no_mangle]
pub fn Arch_configureIdleThread(tcb: *const tcb_t) {
    setRegister(tcb as *mut tcb_t, NextIP, idle_thread as usize);
    setRegister(tcb as *mut tcb_t, SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
    unsafe {
        setRegister(
            tcb as *mut tcb_t,
            sp,
            kernel_stack_alloc.as_ptr() as usize + BIT!(CONFIG_KERNEL_STACK_BITS),
        );
    }
}

#[no_mangle]
pub fn setThreadState(tptr: *mut tcb_t, ts: usize) {
    unsafe {
        thread_state_set_tsType(&mut (*tptr).tcbState, ts);
        scheduleTCB(tptr);
    }
}
#[no_mangle]
pub fn decodeDomainInvocation(invLabel: usize, length: usize, buffer: *mut usize) -> exception_t {
    if invLabel != DomainSetSet {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let domain: usize;
    if length == 0 {
        println!("Domain Configure: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    } else {
        domain = getSyscallArg(0, buffer);
        if domain >= 1 {
            println!("Domain Configure: invalid domain ({} >= 1).", domain);
            unsafe {
                current_syscall_error._type = seL4_InvalidArgument;
                current_syscall_error.invalidArgumentNumber = 0;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
    }
    unsafe {
        if current_extra_caps.excaprefs[0] as usize == 0 {
            println!("Domain Configure: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let tcap = unsafe { &(*current_extra_caps.excaprefs[0]).cap };
    if unlikely(cap_get_capType(tcap) != cap_thread_cap) {
        println!("Domain Configure: thread cap required.");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
        setDomain(cap_thread_cap_get_capTCBPtr(tcap) as *mut tcb_t, domain);
    }
    exception_t::EXCEPTION_NONE
}

// #[no_mangle]
// pub fn testtcb() {
//     let mut arch = arch_tcb_t { registers: [0; 35] };
//     for i in 0..35 {
//         arch.registers[i] = i;
//     }
//     let state = thread_state_t {
//         words: [100, 200, 300],
//     };
//     let mut tcb = tcb_t {
//         tcbArch: arch,
//         tcbMCP: 233,
//         tcbPriority: 198,
//         tcbState: state,
//         domain: 0xffff000000000000usize,
//         tcbBoundNotification: 198 as *mut notification_t,
//         seL4_Fault: seL4_Fault_t {
//             words: [1998, 1999],
//         },
//         tcbLookupFailure: lookup_fault_t {
//             words: [1993, 1994],
//         },
//         tcbTimeSlice: 146,
//         tcbFaultHandler: 129,
//         tcbIPCBuffer: 789,
//         tcbSchedNext: 987,
//         tcbSchedPrev: 897,
//         tcbEPNext: 1467,
//         tcbEPPrev: usize::MAX,
//     };
//     unsafe {
//         parserTcb(&mut tcb as *mut tcb_t);
//     }
// }

#[no_mangle]
pub fn scheduleTCB(tptr: *const tcb_t) {
    unsafe {
        if tptr as usize == ksCurThread as usize
            && ksSchedulerAction as usize == SchedulerAction_ResumeCurrentThread
            && !isRunnable(tptr)
        {
            rescheduleRequired();
        }
    }
}

pub fn getReStartPC(thread: *const tcb_t) -> usize {
    getRegister(thread, FaultIP)
}

pub fn setRestartPC(thread: *mut tcb_t, v: usize) {
    setRegister(thread, NextIP, v);
}

pub fn setNextPC(thread: *mut tcb_t, v: usize) {
    setRegister(thread, NextIP, v);
}

#[no_mangle]
pub fn configureIdleThread(tcb: *const tcb_t) {
    Arch_configureIdleThread(tcb);
    setThreadState(tcb as *mut tcb_t, ThreadStateIdleThreadState);
}

pub fn getCSpace(ptr: usize, i: usize) -> *mut cte_t {
    unsafe {
        let p = (ptr & !MASK!(seL4_TCBBits)) as *mut cte_t;
        p.add(i)
    }
}

#[no_mangle]
pub fn Arch_switchToThread(tcb: *const tcb_t) {
    setVMRoot(tcb as *mut tcb_t);
}

#[inline]
pub fn updateReStartPC(tcb: *mut tcb_t) {
    setRegister(tcb, FaultIP, getRegister(tcb, NextIP));
}

#[no_mangle]
pub fn suspend(target: *mut tcb_t) {
    cancelIPC(target);
    unsafe {
        if thread_state_get_tsType(&(*target).tcbState) == ThreadStateRunning {
            updateReStartPC(target);
        }
        setThreadState(target, ThreadStateInactive);
        tcbSchedDequeue(target);
    }
}

#[no_mangle]
pub fn restart(target: *mut tcb_t) {
    if isStopped(target) {
        cancelIPC(target);
        setupReplyMaster(target);
        setThreadState(target, ThreadStateRestart);
        tcbSchedEnqueue(target);
        possibleSwitchTo(target);
    }
}

#[no_mangle]
pub fn doReplyTransfer(sender: *mut tcb_t, receiver: *mut tcb_t, slot: *mut cte_t, grant: bool) {
    unsafe {
        assert!(thread_state_get_tsType(&(*receiver).tcbState) == ThreadStateBlockedOnReply);
    }
    let fault_type = unsafe { seL4_Fault_get_seL4_FaultType(&(*receiver).tcbFault) };
    if likely(fault_type == seL4_Fault_NullFault) {
        doIPCTransfer(sender, 0 as *mut endpoint_t, 0, grant, receiver);
        cteDeleteOne(slot);
        setThreadState(receiver, ThreadStateRunning);
        possibleSwitchTo(receiver);
    } else {
        cteDeleteOne(slot);
        let restart = handleFaultReply(receiver, sender);

        if restart {
            setThreadState(receiver, ThreadStateRestart);
            possibleSwitchTo(receiver);
        } else {
            setThreadState(receiver, ThreadStateInactive);
        }
    }
}

#[no_mangle]
pub fn doFaultTransfer(
    badge: usize,
    sender: *mut tcb_t,
    receiver: *mut tcb_t,
    receivedIPCBuffer: *mut usize,
) {
    let sent = setMRs_fault(sender, receiver, receivedIPCBuffer);
    let msgInfo = unsafe {
        seL4_MessageInfo_new(
            seL4_Fault_get_seL4_FaultType(&(*sender).tcbFault),
            0,
            0,
            sent,
        )
    };
    setRegister(receiver, msgInfoRegister, wordFromMEssageInfo(msgInfo));
    setRegister(receiver, badgeRegister, badge);
}

#[no_mangle]
pub fn transferCaps(
    info: seL4_MessageInfo_t,
    endpoint: *mut endpoint_t,
    receiver: *mut tcb_t,
    receivedBuffer: *mut usize,
) -> seL4_MessageInfo_t {
    unsafe {
        seL4_MessageInfo_ptr_set_extraCaps(
            (&info) as *const seL4_MessageInfo_t as *mut seL4_MessageInfo_t,
            0,
        );
        seL4_MessageInfo_ptr_set_capsUnwrapped(
            (&info) as *const seL4_MessageInfo_t as *mut seL4_MessageInfo_t,
            0,
        );
        if current_extra_caps.excaprefs[0] as usize == 0 || receivedBuffer as usize == 0 {
            return info;
        }
        let mut destSlot = getReceiveSlots(receiver, receivedBuffer);
        let mut i = 0;
        while i < seL4_MsgMaxExtraCaps && current_extra_caps.excaprefs[i] as usize != 0 {
            let slot = current_extra_caps.excaprefs[i];
            let cap = &(*slot).cap;
            if cap_get_capType(cap) == cap_endpoint_cap
                && (cap_endpoint_cap_get_capEPPtr(cap) == endpoint as usize)
            {
                setExtraBadge(receivedBuffer, cap_endpoint_cap_get_capEPBadge(cap), i);
                seL4_MessageInfo_ptr_set_capsUnwrapped(
                    (&info) as *const seL4_MessageInfo_t as *mut seL4_MessageInfo_t,
                    seL4_MessageInfo_ptr_get_capsUnwrapped((&info) as *const seL4_MessageInfo_t)
                        | (1 << i),
                );
            } else {
                if destSlot as usize == 0 {
                    break;
                }
                let dc_ret = deriveCap(slot, cap);
                if dc_ret.status != exception_t::EXCEPTION_NONE
                    || cap_get_capType(&dc_ret.cap) == cap_null_cap
                {
                    break;
                }
                cteInsert(&dc_ret.cap, slot, destSlot);
                destSlot = 0 as *mut cte_t;
            }
            i += 1;
        }
        seL4_MessageInfo_ptr_set_extraCaps(
            (&info) as *const seL4_MessageInfo_t as *mut seL4_MessageInfo_t,
            i,
        );
        return info;
    }
}

#[no_mangle]
pub fn doNBRecvFailedTransfer(thread: *mut tcb_t) {
    setRegister(thread, badgeRegister, 0);
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
pub fn switchToThread(thread: *const tcb_t) {
    Arch_switchToThread(thread);

    unsafe {
        tcbSchedDequeue(thread as *mut tcb_t);
        ksCurThread = thread as *mut tcb_t;
    }
}

#[no_mangle]
pub fn Arch_switchToIdleThread() {
    unsafe {
        let tcb = ksIdleThread as *mut tcb_t;
        setVMRoot(tcb);
    }
}

#[no_mangle]
pub fn chooseThread() {
    unsafe {
        let dom = 0;
        if ksReadyQueuesL1Bitmap[dom] != 0 {
            let prio = getHighestPrio(dom);
            let thread = ksReadyQueues[ready_queues_index(dom, prio)].head;
            assert!(thread as usize != 0);
            switchToThread(thread);
        } else {
            switchToIdleThread();
        }
    }
}

#[no_mangle]
pub fn switchToIdleThread() {
    unsafe {
        Arch_switchToIdleThread();
        ksCurThread = ksIdleThread;
    }
}

#[no_mangle]
pub fn setDomain(tptr: *mut tcb_t, _dom: usize) {
    if isRunnable(tptr) {
        tcbSchedEnqueue(tptr);
    }
    unsafe {
        if tptr == ksCurThread {
            rescheduleRequired();
        }
    }
}

#[no_mangle]
pub fn setMCPriority(tptr: *mut tcb_t, mcp: usize) {
    unsafe {
        (*tptr).tcbMCP = mcp;
    }
}

#[no_mangle]
pub fn setPriority(tptr: *mut tcb_t, prio: usize) {
    unsafe {
        tcbSchedDequeue(tptr);
        (*tptr).tcbPriority = prio;
        if isRunnable(tptr) {
            if tptr as usize == ksCurThread as usize {
                rescheduleRequired();
            } else {
                possibleSwitchTo(tptr);
            }
        }
    }
}

#[no_mangle]
pub fn timerTick() {
    unsafe {
        if thread_state_get_tsType(&(*ksCurThread).tcbState) == ThreadStateRunning {
            let tcb = &mut (*ksCurThread);
            if tcb.tcbTimeSlice > 1 {
                tcb.tcbTimeSlice -= 1;
            } else {
                tcb.tcbTimeSlice = 5;
                tcbSchedAppend(ksCurThread);
                rescheduleRequired();
            }
        }
    }
}

#[no_mangle]
pub fn possibleSwitchTo(target: *const tcb_t) {
    unsafe {
        if ksCurDomain != (*target).domain {
            tcbSchedEnqueue(target as *mut tcb_t);
        } else if ksSchedulerAction as usize != SchedulerAction_ResumeCurrentThread {
            rescheduleRequired();
            tcbSchedEnqueue(target as *mut tcb_t);
        } else {
            ksSchedulerAction = target as *mut tcb_t;
        }
    }
}

#[no_mangle]
pub fn rescheduleRequired() {
    unsafe {
        if ksSchedulerAction as usize != SchedulerAction_ResumeCurrentThread
            && ksSchedulerAction as usize != SchedulerAction_ChooseNewThread
        {
            tcbSchedEnqueue(ksSchedulerAction as *mut tcb_t);
        }
        ksSchedulerAction = SchedulerAction_ChooseNewThread as *mut tcb_t;
    }
}

#[no_mangle]
pub fn schedule() {
    unsafe {
        if ksSchedulerAction as usize != SchedulerAction_ResumeCurrentThread {
            let was_runnable: bool;
            if isRunnable(ksCurThread as *const tcb_t) {
                was_runnable = true;
                tcbSchedEnqueue(ksCurThread as *mut tcb_t);
            } else {
                was_runnable = false;
            }

            if ksSchedulerAction as usize == SchedulerAction_ChooseNewThread {
                scheduleChooseNewThread();
            } else {
                let candidate = ksSchedulerAction as *mut tcb_t;
                let fastfail = ksCurThread == ksIdleThread
                    || (*candidate).tcbPriority < (*(ksCurThread as *const tcb_t)).tcbPriority;
                if fastfail && !isHighestPrio(ksCurDomain, (*candidate).tcbPriority) {
                    tcbSchedEnqueue(candidate as *mut tcb_t);
                    ksSchedulerAction = SchedulerAction_ChooseNewThread as *mut tcb_t;
                    scheduleChooseNewThread();
                } else if was_runnable
                    && (*candidate).tcbPriority == (*(ksCurThread as *const tcb_t)).tcbPriority
                {
                    tcbSchedAppend(candidate as *mut tcb_t);
                    ksSchedulerAction = SchedulerAction_ChooseNewThread as *mut tcb_t;
                    scheduleChooseNewThread();
                } else {
                    switchToThread(candidate);
                }
            }
        }
        ksSchedulerAction = SchedulerAction_ResumeCurrentThread as *mut tcb_t;
    }
}

pub fn Arch_initContext(mut context: arch_tcb_t) -> arch_tcb_t {
    (context).registers[SSTATUS] = 0x00040020;
    context
}

#[no_mangle]
pub fn doIPCTransfer(
    sender: *mut tcb_t,
    endpoint: *mut endpoint_t,
    badge: usize,
    grant: bool,
    receiver: *mut tcb_t,
) {
    let receiveBuffer = lookupIPCBuffer(true, receiver) as *mut usize;
    unsafe {
        if likely(seL4_Fault_get_seL4_FaultType(&(*sender).tcbFault) == seL4_Fault_NullFault) {
            let sendBuffer = lookupIPCBuffer(false, sender) as *mut usize;
            doNormalTransfer(
                sender,
                sendBuffer,
                endpoint,
                badge,
                grant,
                receiver,
                receiveBuffer,
            );
        } else {
            doFaultTransfer(badge, sender, receiver, receiveBuffer);
        }
    }
}

#[no_mangle]
pub fn doNormalTransfer(
    sender: *mut tcb_t,
    sendBuffer: *mut usize,
    endpoint: *mut endpoint_t,
    badge: usize,
    canGrant: bool,
    receiver: *mut tcb_t,
    receivedBuffer: *mut usize,
) {
    let mut tag = messageInfoFromWord(getRegister(sender, msgInfoRegister));
    if canGrant {
        let status = lookupExtraCaps(sender, sendBuffer, &tag);

        if unlikely(status != exception_t::EXCEPTION_NONE) {
            unsafe {
                current_extra_caps.excaprefs[0] = 0 as *mut cte_t;
            }
        }
    } else {
        unsafe {
            current_extra_caps.excaprefs[0] = 0 as *mut cte_t;
        }
    }
    let msgTransferred = copyMRs(
        sender,
        sendBuffer,
        receiver,
        receivedBuffer,
        seL4_MessageInfo_ptr_get_length((&tag) as *const seL4_MessageInfo_t),
    );

    tag = transferCaps(tag, endpoint, receiver, receivedBuffer);

    seL4_MessageInfo_ptr_set_length(
        (&tag) as *const seL4_MessageInfo_t as *mut seL4_MessageInfo_t,
        msgTransferred,
    );
    setRegister(receiver, msgInfoRegister, wordFromMEssageInfo(tag));
    setRegister(receiver, badgeRegister, badge);
}

#[no_mangle]
pub fn getReceiveSlots(thread: *mut tcb_t, buffer: *mut usize) -> *mut cte_t {
    if buffer as usize == 0 {
        return 0 as *mut cte_t;
    }
    let ct = loadCapTransfer(buffer);
    let cptr = ct.ctReceiveRoot;
    let luc_ret = lookupCap(thread, cptr);
    let cnode = &luc_ret.cap;
    let lus_ret = rust_lookupTargetSlot(cnode, ct.ctReceiveIndex, ct.ctReceiveDepth);
    if lus_ret.status != exception_t::EXCEPTION_NONE {
        return 0 as *mut cte_t;
    }
    unsafe {
        if cap_get_capType(&(*lus_ret.slot).cap) != cap_null_cap {
            return 0 as *mut cte_t;
        }
    }
    lus_ret.slot
}

#[no_mangle]
pub fn loadCapTransfer(buffer: *mut usize) -> cap_transfer_t {
    let offset = seL4_MsgMaxLength + 2 + seL4_MsgMaxExtraCaps;
    unsafe { capTransferFromWords(buffer.add(offset)) }
}

#[no_mangle]
pub fn setExtraBadge(bufferPtr: *mut usize, badge: usize, i: usize) {
    unsafe {
        let ptr = bufferPtr.add(seL4_MsgMaxLength + 2 + i);
        *ptr = badge;
    }
}

#[no_mangle]
pub fn getExtraCPtr(bufferPtr: *mut usize, i: usize) -> usize {
    unsafe {
        let ptr = bufferPtr.add(seL4_MsgMaxLength + 2 + i);
        *ptr
    }
}

#[no_mangle]
pub fn setMRs_syscall_error(thread: *mut tcb_t, receivedIPCBuffer: *mut usize) -> usize {
    unsafe {
        match current_syscall_error._type {
            seL4_InvalidArgument => setMR(
                thread,
                receivedIPCBuffer,
                0,
                current_syscall_error.invalidArgumentNumber,
            ),
            seL4_InvalidCapability => setMR(
                thread,
                receivedIPCBuffer,
                0,
                current_syscall_error.invalidCapNumber,
            ),
            seL4_RangeError => {
                setMR(
                    thread,
                    receivedIPCBuffer,
                    0,
                    current_syscall_error.rangeErrorMin,
                );
                setMR(
                    thread,
                    receivedIPCBuffer,
                    1,
                    current_syscall_error.rangeErrorMax,
                )
            }
            seL4_FailedLookup => {
                let flag = if current_syscall_error.failedLookupWasSource == 1 {
                    true
                } else {
                    false
                };
                setMR(thread, receivedIPCBuffer, 0, flag as usize);
                return setMRs_lookup_failure(thread, receivedIPCBuffer, &current_lookup_fault, 1);
            }
            seL4_IllegalOperation
            | seL4_AlignmentError
            | seL4_TruncatedMessage
            | seL4_DeleteFirst
            | seL4_RevokeFirst => 0,
            seL4_NotEnoughMemory => setMR(
                thread,
                receivedIPCBuffer,
                0,
                current_syscall_error.memoryLeft,
            ),
            _ => panic!("invalid syscall error"),
        }
    }
}

#[no_mangle]
pub fn activateThread() {
    unsafe {
        assert!(ksCurThread as usize != 0 && ksCurThread as usize != 1);
        let thread = ksCurThread;
        match thread_state_get_tsType(&(*thread).tcbState) {
            ThreadStateRunning => {
                return;
            }
            ThreadStateRestart => {
                let pc = getReStartPC(thread);
                setNextPC(thread, pc);
                setThreadState(thread, ThreadStateRunning);
            }
            ThreadStateIdleThreadState => return,
            _ => panic!(
                "current thread is blocked , state id :{}",
                thread_state_get_tsType(&(*thread).tcbState)
            ),
        }
    }
}
