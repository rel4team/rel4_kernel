use crate::{
    config::{
        badgeRegister, frameRegisters, gpRegisters, msgInfoRegister, msgRegister, n_frameRegisters,
        n_gpRegisters, n_msgRegisters, seL4_IllegalOperation, seL4_InvalidCapability, seL4_MinPrio,
        seL4_MsgMaxExtraCaps, seL4_RangeError, seL4_TruncatedMessage, tcbBuffer, tcbCTable,
        tcbCaller, tcbReply, tcbVTable, thread_control_update_ipc_buffer,
        thread_control_update_mcp, thread_control_update_priority, thread_control_update_space,
        CopyRegisters_resumeTarget, CopyRegisters_suspendSource,
        CopyRegisters_transferFrame, CopyRegisters_transferInteger, ReadRegisters_suspend,
        TCBBindNotification, TCBConfigure, TCBCopyRegisters, TCBReadRegisters, TCBResume,
        TCBSetIPCBuffer, TCBSetMCPriority, TCBSetPriority, TCBSetSchedParams, TCBSetSpace,
        TCBSetTLSBase, TCBSuspend, TCBUnbindNotification, TCBWriteRegisters,
        ThreadStateBlockedOnReply, ThreadStateRestart, ThreadStateRunning, CONFIG_NUM_PRIORITIES,
        L2_BITMAP_SIZE,
    },
    kernel::{
        boot::{current_extra_caps, current_syscall_error},
        cspace::lookupSlot,
        thread::{
            getCSpace, getExtraCPtr, getReStartPC, getRegister, ksCurThread, ksReadyQueues,
            ksReadyQueuesL1Bitmap, ksReadyQueuesL2Bitmap, rescheduleRequired, restart,
            setMCPriority, setNextPC, setPriority, setRegister, setThreadState, suspend, TLS_BASE,
        },
        transfermsg::{
            seL4_MessageInfo_new, seL4_MessageInfo_ptr_get_extraCaps, wordFromMessageInfo,
        },
        vspace::{checkValidIPCBuffer, isValidVTableRoot, lookupIPCBuffer},
    },
    object::objecttype::updateCapData,
    println,
    structures::{
        notification_t, seL4_MessageInfo_t, tcb_queue_t, tcb_t,
    },
    syscall::getSyscallArg,
};

use super::{
    cap::{cteDelete, cteDeleteOne},
    // cap::cteDelete,
    notification::{bindNotification, unbindNotification},
    structure_gen::{notification_ptr_get_ntfnQueue_head, notification_ptr_get_ntfnQueue_tail,
        thread_state_get_tcbQueued, thread_state_set_tcbQueued,
    },
};

use common::{structures::exception_t, sel4_config::*, BIT, MASK};
use cspace::interface::*;

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

#[no_mangle]
pub fn checkPrio(prio: usize, auth: *mut tcb_t) -> exception_t {
    unsafe {
        let mcp = (*auth).tcbMCP;
        if prio > mcp {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = seL4_MinPrio;
            current_syscall_error.rangeErrorMax = mcp;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        exception_t::EXCEPTION_NONE
    }
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
pub fn tcbSchedEnqueue(_tcb: *mut tcb_t) {
    unsafe {
        let tcb = &mut (*_tcb);
        if thread_state_get_tcbQueued(&tcb.tcbState) == 0 {
            let dom = tcb.domain;
            let prio = tcb.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = ksReadyQueues[idx];
            if queue.tail as usize == 0 {
                queue.head = _tcb;
                addToBitmap(dom, prio);
            } else {
                (*(queue.tail as *mut tcb_t)).tcbSchedNext = _tcb as usize;
            }
            (*_tcb).tcbSchedPrev = queue.tail as usize;
            (*_tcb).tcbSchedNext = 0;
            queue.tail = _tcb;
            ksReadyQueues[idx] = queue;

            thread_state_set_tcbQueued(&mut tcb.tcbState, 1);
        }
    }
}

#[inline]
#[no_mangle]
pub fn tcbSchedDequeue(_tcb: *mut tcb_t) {
    unsafe {
        let tcb = &mut (*_tcb);
        if thread_state_get_tcbQueued(&tcb.tcbState) != 0 {
            let dom = tcb.domain;
            let prio = tcb.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = ksReadyQueues[idx];
            if tcb.tcbSchedPrev != 0 {
                (*(tcb.tcbSchedPrev as *mut tcb_t)).tcbSchedNext = tcb.tcbSchedNext;
            } else {
                queue.head = tcb.tcbSchedNext as *mut tcb_t;
                if tcb.tcbSchedNext == 0 {
                    removeFromBitmap(dom, prio);
                }
            }
            if tcb.tcbSchedNext != 0 {
                (*(tcb.tcbSchedNext as *mut tcb_t)).tcbSchedPrev = tcb.tcbSchedPrev;
            } else {
                queue.tail = tcb.tcbSchedPrev as *mut tcb_t;
            }

            ksReadyQueues[idx] = queue;
            thread_state_set_tcbQueued(&mut tcb.tcbState, 0);
        }
    }
}

#[no_mangle]
pub fn tcbSchedAppend(tcb: *mut tcb_t) {
    unsafe {
        if thread_state_get_tcbQueued(&(*tcb).tcbState) == 0 {
            let dom = (*tcb).domain;
            let prio = (*tcb).tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let mut queue = ksReadyQueues[idx];

            if queue.head as usize == 0 {
                queue.head = tcb;
                addToBitmap(dom, prio);
            } else {
                let next = queue.tail;
                (*next).tcbSchedNext = tcb as usize;
            }
            (*tcb).tcbSchedPrev = queue.tail as usize;
            (*tcb).tcbSchedNext = 0;
            queue.tail = tcb;
            ksReadyQueues[idx] = queue;

            thread_state_set_tcbQueued(&mut (*tcb).tcbState, 1);
        }
    }
}

#[no_mangle]
pub fn tcbEPAppend(tcb: *mut tcb_t, mut queue: tcb_queue_t) -> tcb_queue_t {
    unsafe {
        if queue.head as usize == 0 {
            queue.head = tcb;
        } else {
            (*(queue.tail as *mut tcb_t)).tcbEPNext = tcb as usize;
        }
        (*tcb).tcbEPPrev = queue.tail as usize;
        (*tcb).tcbEPNext = 0;
        queue.tail = tcb as *mut tcb_t;
        queue
    }
}

#[no_mangle]
pub fn tcbEPDequeue(tcb: *mut tcb_t, mut queue: tcb_queue_t) -> tcb_queue_t {
    unsafe {
        if (*tcb).tcbEPPrev != 0 {
            (*((*tcb).tcbEPPrev as *mut tcb_t)).tcbEPNext = (*tcb).tcbEPNext;
        } else {
            queue.head = (*tcb).tcbEPNext as *mut tcb_t;
        }
        if (*tcb).tcbEPNext != 0 {
            (*((*tcb).tcbEPNext as *mut tcb_t)).tcbEPPrev = (*tcb).tcbEPPrev;
        } else {
            queue.tail = (*tcb).tcbEPPrev as *mut tcb_t;
        }
        queue
    }
}

#[no_mangle]
pub fn setupCallerCap(sender: *const tcb_t, receiver: *const tcb_t, canGrant: bool) {
    unsafe {
        setThreadState(sender as *mut tcb_t, ThreadStateBlockedOnReply);
        let replySlot = getCSpace(sender as usize, tcbReply);
        let masterCap = &(*replySlot).cap;

        assert!(cap_get_capType(masterCap) == cap_reply_cap);
        assert!(cap_reply_cap_get_capReplyMaster(masterCap) == 1);
        assert!(cap_reply_cap_get_capReplyCanGrant(masterCap) == 1);
        assert!(cap_reply_cap_get_capTCBPtr(masterCap) == sender as usize);

        let callerSlot = getCSpace(receiver as usize, tcbCaller);
        let callerCap = &(*callerSlot).cap;

        assert!(cap_get_capType(callerCap) == cap_null_cap);
        cteInsert(
            &cap_reply_cap_new(canGrant as usize, 0, sender as usize),
            replySlot,
            callerSlot,
        );
    }
}

#[no_mangle]
pub fn deleteCallerCap(receiver: *mut tcb_t) {
    let callerSlot = getCSpace(receiver as usize, tcbCaller);
    cteDeleteOne(callerSlot);
}

#[no_mangle]
pub fn lookupExtraCaps(
    thread: *mut tcb_t,
    bufferPtr: *mut usize,
    info: &seL4_MessageInfo_t,
) -> exception_t {
    unsafe {
        if bufferPtr as usize == 0 {
            current_extra_caps.excaprefs[0] = 0 as *mut cte_t;
            return exception_t::EXCEPTION_NONE;
        }
        let length = seL4_MessageInfo_ptr_get_extraCaps(info as *const seL4_MessageInfo_t);
        let mut i = 0;
        while i < length {
            let cptr = getExtraCPtr(bufferPtr, i);
            let lu_ret = lookupSlot(thread, cptr);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                panic!(" lookup slot error , found slot :{}", lu_ret.slot as usize);
            }
            current_extra_caps.excaprefs[i] = lu_ret.slot;
            i += 1;
        }
        if i < seL4_MsgMaxExtraCaps {
            current_extra_caps.excaprefs[i] = 0 as *mut cte_t;
        }
        return exception_t::EXCEPTION_NONE;
    }
}

#[no_mangle]
pub fn copyMRs(
    sender: *mut tcb_t,
    sendBuf: *mut usize,
    receiver: *mut tcb_t,
    recvBuf: *mut usize,
    n: usize,
) -> usize {
    let mut i = 0;
    while i < n && i < n_msgRegisters {
        setRegister(
            receiver,
            msgRegister[i],
            getRegister(sender, msgRegister[i]),
        );
        i += 1;
    }

    if recvBuf as usize == 0 || sendBuf as usize == 0 {
        return i;
    }

    while i < n {
        unsafe {
            let recvPtr = recvBuf.add(i + 1);
            let sendPtr = sendBuf.add(i + 1);
            *recvPtr = *sendPtr;
            i += 1;
        }
    }
    i
}

#[no_mangle]
pub fn decodeCopyRegisters(cap: &cap_t, _length: usize, buffer: *mut usize) -> exception_t {
    let flags = getSyscallArg(0, buffer);
    let source_cap: &cap_t;
    unsafe {
        source_cap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(cap) != cap_thread_cap {
        unsafe {
            println!("TCB CopyRegisters: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let srcTCB = cap_thread_cap_get_capTCBPtr(source_cap) as *mut tcb_t;
    return invokeTCB_CopyRegisters(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        srcTCB,
        flags & BIT!(CopyRegisters_suspendSource),
        flags & BIT!(CopyRegisters_resumeTarget),
        flags & BIT!(CopyRegisters_transferFrame),
        flags & BIT!(CopyRegisters_transferInteger),
        0,
    );
}

#[no_mangle]
pub fn invokeTCB_CopyRegisters(
    dest: *mut tcb_t,
    src: *mut tcb_t,
    suspendSource: usize,
    resumeTarget: usize,
    transferFrame: usize,
    _transferInteger: usize,
    _transferArch: usize,
) -> exception_t {
    if suspendSource != 0 {
        suspend(src);
    }
    if resumeTarget != 0 {
        restart(dest);
    }
    if transferFrame != 0 {
        for i in 0..n_gpRegisters {
            let v = getRegister(src, gpRegisters[i]);
            setRegister(dest, gpRegisters[i], v);
        }
    }
    unsafe {
        if dest == ksCurThread {
            rescheduleRequired();
        }
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn decodeReadRegisters(
    cap: &cap_t,
    length: usize,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    if length < 2 {
        unsafe {
            println!("TCB CopyRegisters: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let flags = getSyscallArg(0, buffer);
    let n = getSyscallArg(1, buffer);
    if n < 1 || n > n_frameRegisters + n_gpRegisters {
        println!(
            "TCB ReadRegisters: Attempted to read an invalid number of registers:{}",
            n
        );
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = n_frameRegisters + n_gpRegisters;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        let thread = cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t;
        if thread == ksCurThread {
            println!("TCB ReadRegisters: Attempted to read our own registers.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }

        // let source_cap = &(*current_extra_caps.excaprefs[0]).cap;
        // if cap_get_capType(source_cap) != cap_thread_cap {
        //     panic!("TCB CopyRegisters: Invalid source TCB");
        // }
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
        invokeTCB_ReadRegisters(
            cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
            flags & BIT!(ReadRegisters_suspend),
            n,
            0,
            call,
        )
    }
}

#[no_mangle]
pub fn invokeTCB_ReadRegisters(
    src: *mut tcb_t,
    suspendSource: usize,
    n: usize,
    _arch: usize,
    call: bool,
) -> exception_t {
    let thread: *mut tcb_t;
    unsafe {
        thread = ksCurThread as *mut tcb_t;
    }
    if suspendSource != 0 {
        suspend(src);
    }

    if call {
        let ipcBuffer = lookupIPCBuffer(true, thread) as *mut usize;
        setRegister(thread, badgeRegister, 0);
        let mut i: usize = 0;
        while i < n && i < n_frameRegisters && i < n_msgRegisters {
            setRegister(thread, msgRegister[i], getRegister(src, frameRegisters[i]));
            i += 1;
        }

        if ipcBuffer as usize != 0 && i < n && i < n_frameRegisters {
            while i < n && i < n_frameRegisters {
                unsafe {
                    let ptr = ipcBuffer.add(i + 1) as *mut usize;
                    *ptr = getRegister(src, frameRegisters[i]);
                }
                i += 1;
            }
        }

        let j = i;
        i = 0;
        while i < n_gpRegisters && i + n_frameRegisters < n && i + n_frameRegisters < n_msgRegisters
        {
            setRegister(
                thread,
                msgRegister[i + n_frameRegisters],
                getRegister(src, gpRegisters[i]),
            );
            i += 1;
        }
        if ipcBuffer as usize != 0 && i < n_gpRegisters && i + n_frameRegisters < n {
            while i < n_gpRegisters && i + n_frameRegisters < n {
                let ptr = unsafe { ipcBuffer.add(i + n_frameRegisters + 1) };
                unsafe {
                    *ptr = getRegister(src, gpRegisters[i]);
                }
                i += 1;
            }
        }
        setRegister(
            thread,
            msgInfoRegister,
            wordFromMessageInfo(seL4_MessageInfo_new(0, 0, 0, i + j)),
        );
    }
    setThreadState(thread, ThreadStateRunning);
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn invokeTCB_WriteRegisters(
    dest: *mut tcb_t,
    resumeTarget: usize,
    _n: usize,
    _arch: usize,
    buffer: *mut usize,
) -> exception_t {
    let mut n: usize = _n;
    if n > n_frameRegisters + n_gpRegisters {
        n = n_frameRegisters + n_gpRegisters;
    }

    let mut i = 0;

    while i < n_frameRegisters && i < n {
        setRegister(dest, frameRegisters[i], getSyscallArg(i + 2, buffer));
        i += 1;
    }
    i = 0;
    while i < n_gpRegisters && i + n_frameRegisters < n {
        setRegister(
            dest,
            gpRegisters[i],
            getSyscallArg(i + n_frameRegisters + 2, buffer),
        );
        i += 1;
    }

    let pc = getReStartPC(dest);
    setNextPC(dest, pc);

    if resumeTarget != 0 {
        restart(dest);
    }
    unsafe {
        if dest == ksCurThread {
            rescheduleRequired();
        }
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn decodeWriteRegisters(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    if length < 2 {
        unsafe {
            println!("TCB CopyRegisters: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let flags = getSyscallArg(0, buffer);
    let w = getSyscallArg(1, buffer);

    if length - 2 < w {
        println!(
            "TCB WriteRegisters: Message too short for requested write size {}/{}",
            length - 2,
            w
        );
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let thread = cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t;
    unsafe {
        if thread == ksCurThread {
            println!("TCB WriteRegisters: Attempted to write our own registers.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_WriteRegisters(thread, flags & BIT!(0), w, 0, buffer)
}

#[no_mangle]
pub fn decodeTCBConfigure(
    cap: &cap_t,
    length: usize,
    slot: *mut cte_t,
    buffer: *mut usize,
) -> exception_t {
    let mut bufferCap: cap_t;
    let mut cRootCap: cap_t;
    let mut vRootCap: cap_t;
    let mut dc_ret: deriveCap_ret;
    let mut bufferSlot: *mut cte_t;
    let cRootSlot: *mut cte_t;
    let vRootSlot: *mut cte_t;
    let cRootData: usize;
    let vRootData: usize;
    let bufferAddr: usize;

    unsafe {
        if length < 4
            || current_extra_caps.excaprefs[0] as usize == 0
            || current_extra_caps.excaprefs[1] as usize == 0
            || current_extra_caps.excaprefs[2] as usize == 0
        {
            println!("TCB CopyRegisters: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let faultEP = getSyscallArg(0, buffer);
    cRootData = getSyscallArg(1, buffer);
    vRootData = getSyscallArg(2, buffer);
    bufferAddr = getSyscallArg(3, buffer);

    unsafe {
        cRootSlot = current_extra_caps.excaprefs[0];
        cRootCap = (*current_extra_caps.excaprefs[0]).cap.clone();
        vRootSlot = current_extra_caps.excaprefs[1];
        vRootCap = (*current_extra_caps.excaprefs[1]).cap.clone();
        bufferSlot = current_extra_caps.excaprefs[2];
        bufferCap = (*current_extra_caps.excaprefs[2]).cap.clone();
    }

    if bufferAddr == 0 {
        bufferSlot = 0 as *mut cte_t;
    } else {
        dc_ret = deriveCap(bufferSlot, &bufferCap);
        if dc_ret.status != exception_t::EXCEPTION_NONE {
            unsafe {
                current_syscall_error._type = seL4_IllegalOperation;
            }
            return dc_ret.status;
        }
        bufferCap = dc_ret.cap.clone();

        let e = checkValidIPCBuffer(bufferAddr, &bufferCap);
        if e != exception_t::EXCEPTION_NONE {
            return e;
        }
    }
    unsafe {
        if slotCapLongRunningDelete(getCSpace(cap_thread_cap_get_capTCBPtr(cap), tcbCTable))
            || slotCapLongRunningDelete(getCSpace(cap_thread_cap_get_capTCBPtr(cap), tcbVTable))
        {
            println!("TCB Configure: CSpace or VSpace currently being deleted.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    if cRootData != 0 {
        cRootCap = updateCapData(false, cRootData, &mut cRootCap).clone();
    }

    dc_ret = deriveCap(cRootSlot, &cRootCap);
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return dc_ret.status;
    }
    cRootCap = dc_ret.cap.clone();

    if cap_get_capType(&cRootCap) != cap_cnode_cap {
        println!("TCB Configure: CSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if vRootData != 0 {
        vRootCap = updateCapData(false, vRootData, &mut vRootCap).clone();
    }

    dc_ret = deriveCap(vRootSlot, &vRootCap);
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return dc_ret.status;
    }
    vRootCap = dc_ret.cap.clone();

    if !isValidVTableRoot(&vRootCap) {
        println!("TCB Configure: VSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        slot,
        faultEP,
        0,
        0,
        cRootCap.clone(),
        cRootSlot,
        vRootCap.clone(),
        vRootSlot,
        bufferAddr,
        bufferCap.clone(),
        bufferSlot,
        thread_control_update_space | thread_control_update_ipc_buffer,
    )
}


#[no_mangle]
pub fn invokeTCB_ThreadControl(
    target: *mut tcb_t,
    slot: *mut cte_t,
    faultep: usize,
    mcp: usize,
    prio: usize,
    cRoot_newCap: cap_t,
    cRoot_srcSlot: *mut cte_t,
    vRoot_newCap: cap_t,
    vRoot_srcSlot: *mut cte_t,
    bufferAddr: usize,
    bufferCap: cap_t,
    bufferSrcSlot: *mut cte_t,
    updateFlags: usize,
) -> exception_t {
    unsafe {
        // println!("faultep:{}", faultep);
        // println!("target :{:#x} slot:{:#x}", target as usize, slot as usize);
        // println!("mcp :{} , prio :{}", mcp, prio);
        // println!("updateFlags :{}", updateFlags);
        // println!(
        //     "cRoot_newCap :{:#x} {:#x}",
        //     cRoot_newCap.words[0], cRoot_newCap.words[1]
        // );
        // println!(
        //     "vRoot_newCap :{:#x} {:#x}",
        //     vRoot_newCap.words[0], vRoot_newCap.words[1]
        // );
        // println!(
        //     "bufferCap :{:#x} {:#x}",
        //     bufferCap.words[0], bufferCap.words[1]
        // );
        // println!(
        //     "addr :{:#x} {:#x} {:#x} {:#x}",
        //     cRoot_srcSlot as usize,
        //     vRoot_srcSlot as usize,
        //     bufferAddr as usize,
        //     bufferSrcSlot as usize
        // );
        let tCap = &cap_thread_cap_new(target as usize);

        if updateFlags & thread_control_update_mcp != 0 {
            setMCPriority(target, mcp);
        }
        if updateFlags & thread_control_update_space != 0 {
            (*target).tcbFaultHandler = faultep;

            let rootSlot = getCSpace(target as usize, tcbCTable);
            let e = cteDelete(rootSlot, true);
            if e != exception_t::EXCEPTION_NONE {
                return e;
            }
            if sameObjectAs(&cRoot_newCap, &(*cRoot_srcSlot).cap)
                && sameObjectAs(tCap, &(*slot).cap)
            {
                cteInsert(&cRoot_newCap.clone(), cRoot_srcSlot, rootSlot);
            }

            let rootVSlot = getCSpace(target as usize, tcbVTable);
            let e = cteDelete(rootVSlot, true);
            if e != exception_t::EXCEPTION_NONE {
                return e;
            }
            if sameObjectAs(&vRoot_newCap, &(*vRoot_srcSlot).cap)
                && sameObjectAs(tCap, &(*slot).cap)
            {
                cteInsert(&vRoot_newCap.clone(), vRoot_srcSlot, rootVSlot);
            }
        }

        if (updateFlags & thread_control_update_ipc_buffer) != 0 {
            let bufferSlot = getCSpace(target as usize, tcbBuffer);
            let e = cteDelete(bufferSlot, true);
            if e != exception_t::EXCEPTION_NONE {
                return e;
            }
            (*target).tcbIPCBuffer = bufferAddr;
            if bufferSrcSlot as usize != 0
                && sameObjectAs(&bufferCap, &(*bufferSrcSlot).cap)
                && sameObjectAs(tCap, &(*slot).cap)
            {
                cteInsert(&bufferCap.clone(), bufferSrcSlot, bufferSlot);
            }
            if target == ksCurThread {
                rescheduleRequired();
            }
        }
        if (updateFlags & thread_control_update_priority) != 0 {
            setPriority(target, prio);
        }
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn decodeSetMCPriority(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    unsafe {
        if length < 1 || current_extra_caps.excaprefs[0] as usize == 0 {
            println!("TCB SetMCPPriority: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let newMcp = getSyscallArg(0, buffer);
    let authCap: &cap_t;
    unsafe {
        authCap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(authCap) != cap_thread_cap {
        println!("SetMCPriority: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let authTCB = cap_thread_cap_get_capTCBPtr(authCap) as *mut tcb_t;
    let status = checkPrio(newMcp, authTCB);
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            println!(
                "TCB SetMCPriority: Requested maximum controlled priority {} too high (max {}).",
                newMcp,
                (*authTCB).tcbMCP
            );
        }
        return status;
    }
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        0 as *mut cte_t,
        0,
        newMcp,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cap_null_cap_new(),
        0 as *mut cte_t,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        thread_control_update_mcp,
    )
}

#[no_mangle]
pub fn decodeSetSchedParams(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    unsafe {
        if length < 2 || current_extra_caps.excaprefs[0] as usize == 0 {
            println!("TCB SetSchedParams: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let newMcp = getSyscallArg(0, buffer);
    let newPrio = getSyscallArg(1, buffer);
    let authCap: &cap_t;
    unsafe {
        authCap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(authCap) != cap_thread_cap {
        println!("SetSchedParams: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let authTCB = cap_thread_cap_get_capTCBPtr(authCap) as *mut tcb_t;
    let mut status = checkPrio(newMcp, authTCB);
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            println!(
                "TCB SetSchedParams: Requested maximum controlled priority {} too high (max {}).",
                newMcp,
                (*authTCB).tcbMCP
            );
            return status;
        }
    }
    status = checkPrio(newPrio, authTCB);
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            println!(
                "TCB SetSchedParams: Requested priority {} too high (max {}).",
                newPrio,
                (*authTCB).tcbMCP
            );
            return status;
        }
    }
    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        0 as *mut cte_t,
        0,
        newMcp,
        newPrio,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cap_null_cap_new(),
        0 as *mut cte_t,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        thread_control_update_mcp | thread_control_update_priority,
    )
}

#[no_mangle]
pub fn decodeSetIPCBuffer(
    cap: &cap_t,
    length: usize,
    slot: *mut cte_t,
    buffer: *mut usize,
) -> exception_t {
    unsafe {
        if length < 1 || current_extra_caps.excaprefs[0] as usize == 0 {
            println!("TCB SetIPCBuffer: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let cptr_bufferPtr = getSyscallArg(0, buffer);
    let mut bufferSlot: *mut cte_t;
    let mut bufferCap: &cap_t;
    let dc_ret: deriveCap_ret;
    unsafe {
        bufferSlot = current_extra_caps.excaprefs[0] as *mut cte_t;
        bufferCap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cptr_bufferPtr == 0 {
        bufferSlot = 0 as *mut cte_t;
    } else {
        dc_ret = deriveCap(bufferSlot, bufferCap);
        if dc_ret.status != exception_t::EXCEPTION_NONE {
            unsafe {
                current_syscall_error._type = seL4_IllegalOperation;
            }
            return dc_ret.status;
        }
        bufferCap = &dc_ret.cap;
        let e = checkValidIPCBuffer(cptr_bufferPtr, bufferCap);
        if e != exception_t::EXCEPTION_NONE {
            return e;
        }
    }
    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        slot,
        0,
        0,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cptr_bufferPtr,
        bufferCap.clone(),
        bufferSlot,
        thread_control_update_ipc_buffer,
    )
}

#[no_mangle]
pub fn decodeSetSpace(
    cap: &cap_t,
    length: usize,
    slot: *mut cte_t,
    buffer: *mut usize,
) -> exception_t {
    unsafe {
        if length < 3
            || current_extra_caps.excaprefs[0] as usize == 0
            || current_extra_caps.excaprefs[1] as usize == 0
        {
            println!("TCB SetSpace: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let faultEP = getSyscallArg(0, buffer);
    let cRootData = getSyscallArg(1, buffer);
    let vRootData = getSyscallArg(2, buffer);

    let cRootSlot: *mut cte_t;
    let mut cRootCap: cap_t;
    let vRootSlot: *mut cte_t;
    let mut vRootCap: cap_t;
    unsafe {
        cRootSlot = current_extra_caps.excaprefs[0];
        cRootCap = (*current_extra_caps.excaprefs[0]).cap.clone();
        vRootSlot = current_extra_caps.excaprefs[1];
        vRootCap = (*current_extra_caps.excaprefs[1]).cap.clone();
    }

    unsafe {
        if slotCapLongRunningDelete(getCSpace(cap_thread_cap_get_capTCBPtr(cap), tcbCTable))
            || slotCapLongRunningDelete(getCSpace(cap_thread_cap_get_capTCBPtr(cap), tcbVTable))
        {
            println!("TCB Configure: CSpace or VSpace currently being deleted.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if cRootData as usize != 0 {
        cRootCap = updateCapData(false, cRootData, &mut cRootCap).clone();
    }
    let dc_ret1 = deriveCap(cRootSlot, &cRootCap);
    if dc_ret1.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return dc_ret1.status;
    }
    cRootCap = dc_ret1.cap.clone();
    if cap_get_capType(&cRootCap) != cap_cnode_cap {
        println!("TCB Configure: CSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if vRootData as usize != 0 {
        vRootCap = updateCapData(false, vRootData, &mut vRootCap);
    }
    let dc_ret = deriveCap(vRootSlot, &vRootCap);
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return dc_ret.status;
    }
    vRootCap = dc_ret.cap.clone();
    if !isValidVTableRoot(&vRootCap) {
        println!("TCB Configure: VSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }

    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        slot as *mut cte_t,
        faultEP,
        0,
        0,
        cRootCap.clone(),
        cRootSlot as *mut cte_t,
        vRootCap.clone(),
        vRootSlot as *mut cte_t,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        thread_control_update_space,
    )
}

// #[no_mangle]
// pub fn process4(
//     cap: &cap_t,
//     faultEP: usize,
//     slot: *mut cte_t,
//     mut cRootCap: &mut cap_t,
//     cRootSlot: *mut cte_t,
//     mut vRootCap: &mut cap_t,
//     vRootSlot: *mut cte_t,
//     vRootData: usize,
//     cRootData: usize,
// ) -> exception_t {
//     let mut c: cap_t = cRootCap.clone();
//     if cRootData as usize != 0 {
//         c = unsafe { updateCapData(false, cRootData, &mut cRootCap).clone() };
//     }
//     println!("here cRootCap:{:#x} {:#x}", c.words[0], c.words[1]);
//     let dc_ret1 = deriveCap(cRootSlot, &c.clone());
//     if dc_ret1.status != exception_t::EXCEPTION_NONE {
//         return dc_ret1.status;
//     }
//     c = dc_ret1.cap.clone();
//     if cap_get_capType(&c) != cap_cnode_cap {
//         println!("TCB Configure: CSpace cap is invalid.");
//         unsafe {
//             current_syscall_error._type = seL4_IllegalOperation;
//             return exception_t::EXCEPTION_SYSCALL_ERROR;
//         }
//     }

//     let mut v: cap_t = vRootCap.clone();
//     if vRootData as usize != 0 {
//         v = unsafe { updateCapData(false, vRootData, &mut vRootCap.clone()) };
//     }
//     let dc_ret = deriveCap(vRootSlot, &vRootCap);
//     if dc_ret.status != exception_t::EXCEPTION_NONE {
//         return dc_ret.status;
//     }
//     v = dc_ret.cap.clone();

//     if !isValidVTableRoot(&v) {
//         println!("TCB Configure: VSpace cap is invalid.");
//         unsafe {
//             current_syscall_error._type = seL4_IllegalOperation;
//             return exception_t::EXCEPTION_SYSCALL_ERROR;
//         }
//     }

//     unsafe {
//         setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
//     }

//     invokeTCB_ThreadControl(
//         cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
//         slot as *mut cte_t,
//         faultEP,
//         0,
//         0,
//         c.clone(),
//         cRootSlot as *mut cte_t,
//         v.clone(),
//         vRootSlot as *mut cte_t,
//         0,
//         cap_null_cap_new(),
//         0 as *mut cte_t,
//         thread_control_update_space,
//     )
// }

#[no_mangle]
pub fn decodeBindNotification(cap: &cap_t) -> exception_t {
    unsafe {
        if current_extra_caps.excaprefs[0] as usize == 0 {
            println!("TCB BindNotification: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let tcb = cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t;
    let ntfnPtr: *mut notification_t;
    unsafe {
        if (*tcb).tcbBoundNotification as usize != 0 {
            println!("TCB BindNotification: TCB already has a bound notification.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let ntfn_cap: &cap_t;
    unsafe {
        ntfn_cap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(ntfn_cap) == cap_notification_cap {
        ntfnPtr = cap_notification_cap_get_capNtfnPtr(ntfn_cap) as *mut notification_t;
    } else {
        println!("TCB BindNotification: Notification is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    if cap_notification_cap_get_capNtfnCanReceive(ntfn_cap) == 0 {
        println!("TCB BindNotification: Insufficient access rights");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if notification_ptr_get_ntfnQueue_head(ntfnPtr) != 0
        || notification_ptr_get_ntfnQueue_tail(ntfnPtr) != 0
    {
        println!("TCB BindNotification: Notification cannot be bound.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_NotificationControl(tcb, ntfnPtr)
}

#[no_mangle]
pub fn invokeTCB_NotificationControl(tcb: *mut tcb_t, ntfnPtr: *mut notification_t) -> exception_t {
    if ntfnPtr as usize != 0 {
        bindNotification(tcb, ntfnPtr);
    } else {
        unbindNotification(tcb);
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn decodeSetPriority(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    unsafe {
        if length < 1 || current_extra_caps.excaprefs[0] as usize == 0 {
            println!("TCB SetPriority: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let newPrio = getSyscallArg(0, buffer);
    let authCap: &cap_t;
    unsafe {
        authCap = &(*current_extra_caps.excaprefs[0]).cap;
    }
    if cap_get_capType(authCap) != cap_thread_cap {
        println!("Set priority: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let authTCB = cap_thread_cap_get_capTCBPtr(authCap) as *mut tcb_t;
    let status = checkPrio(newPrio, authTCB);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
    }
    invokeTCB_ThreadControl(
        cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t,
        0 as *mut cte_t,
        0,
        0,
        newPrio,
        cap_null_cap_new(),
        0 as *mut cte_t,
        cap_null_cap_new(),
        0 as *mut cte_t,
        0,
        cap_null_cap_new(),
        0 as *mut cte_t,
        thread_control_update_priority,
    )
}

#[no_mangle]
pub fn decodeUnbindNotification(cap: &cap_t) -> exception_t {
    let tcb = cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t;
    unsafe {
        if (*tcb).tcbBoundNotification as usize == 0 {
            println!("TCB BindNotification: TCB already has a bound notification.");
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }

        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    invokeTCB_NotificationControl(tcb, 0 as *mut notification_t)
}

#[no_mangle]
pub fn invokeTCB_Suspend(thread: *mut tcb_t) -> exception_t {
    suspend(thread);
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn invokeTCB_Resume(thread: *mut tcb_t) -> exception_t {
    restart(thread);
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn invokeSetTLSBase(thread: *mut tcb_t, base: usize) -> exception_t {
    setRegister(thread, TLS_BASE, base);
    unsafe {
        if thread == ksCurThread {
            rescheduleRequired();
        }
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn decodeSetTLSBase(cap: &cap_t, length: usize, buffer: *mut usize) -> exception_t {
    if length < 1 {
        println!("TCB SetTLSBase: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let base = getSyscallArg(0, buffer);
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
    }
    invokeSetTLSBase(cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t, base)
}

#[no_mangle]
pub fn decodeTCBInvocation(
    invLabel: usize,
    length: usize,
    cap: &cap_t,
    slot: *mut cte_t,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    match invLabel {
        TCBReadRegisters => decodeReadRegisters(cap, length, call, buffer),
        TCBWriteRegisters => decodeWriteRegisters(cap, length, buffer),
        TCBCopyRegisters => decodeCopyRegisters(cap, length, buffer),
        TCBSuspend => unsafe {
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            invokeTCB_Suspend(cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t)
        },
        TCBResume => unsafe {
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            invokeTCB_Resume(cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t)
        },
        TCBConfigure => decodeTCBConfigure(cap, length, slot, buffer),
        TCBSetPriority => decodeSetPriority(cap, length, buffer),
        TCBSetMCPriority => decodeSetMCPriority(cap, length, buffer),
        TCBSetSchedParams => decodeSetSchedParams(cap, length, buffer),
        TCBSetIPCBuffer => decodeSetIPCBuffer(cap, length, slot as *mut cte_t, buffer),
        TCBSetSpace => decodeSetSpace(cap, length, slot as *mut cte_t, buffer),
        TCBBindNotification => decodeBindNotification(cap),
        TCBUnbindNotification => decodeUnbindNotification(cap),
        TCBSetTLSBase => decodeSetTLSBase(cap, length, buffer),
        _ => unsafe {
            println!("TCB: Illegal operation invLabel :{}", invLabel);
            current_syscall_error._type = seL4_IllegalOperation;
            exception_t::EXCEPTION_SYSCALL_ERROR
        },
    }
}
