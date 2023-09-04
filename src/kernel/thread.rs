use crate::{
    config::{
        CONFIG_KERNEL_STACK_BITS, SSTATUS_SPIE, SSTATUS_SPP, n_msgRegisters, msgRegister,
    },
    object::tcb::{
        copyMRs, lookupExtraCaps
    },
    structures::cap_transfer_t, syscall::getSyscallArg,
};

use task_manager::*;
use ipc::*;
use core::{
    arch::asm,
    intrinsics::{likely, unlikely},
};
use common::{message_info::*, utils::convert_to_type_ref, structures::seL4_IPCBuffer};

use super::{
    boot::{
        current_extra_caps, current_lookup_fault, current_syscall_error,
    },
    cspace::{lookupCap, rust_lookupTargetSlot},
    fault::{handleFaultReply, setMRs_fault, setMRs_lookup_failure},
    transfermsg::capTransferFromWords,
};

use common::{structures::{exception_t, seL4_Fault_get_seL4_FaultType}, BIT, sel4_config::*};
use cspace::interface::*;
use log::debug;

#[no_mangle]
pub static mut kernel_stack_alloc: [[u8; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES] =
    [[0; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES];


pub fn create_idle_thread() {
    unsafe {
        let pptr = ksIdleThreadTCB.as_ptr() as *mut usize;
        ksIdleThread = pptr.add(TCB_OFFSET) as *mut tcb_t;
        // configureIdleThread(ksIdleThread as *const tcb_t);
        let tcb = ksIdleThread as *mut tcb_t;
        setRegister(tcb, NextIP, idle_thread as usize);
        setRegister(tcb, SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
        setRegister(
            tcb,
            sp,
            kernel_stack_alloc.as_ptr() as usize + BIT!(CONFIG_KERNEL_STACK_BITS),
        );
        setThreadState(tcb, ThreadStateIdleThreadState);
    }
}

pub fn idle_thread() {
    unsafe {
        while true {
            asm!("wfi");
        }
    }
}

#[no_mangle]
pub fn decodeDomainInvocation(invLabel: MessageLabel, length: usize, buffer: *mut usize) -> exception_t {
    if invLabel != MessageLabel::DomainSetSet {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let domain: usize;
    if length == 0 {
        debug!("Domain Configure: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    } else {
        domain = getSyscallArg(0, buffer);
        if domain >= 1 {
            debug!("Domain Configure: invalid domain ({} >= 1).", domain);
            unsafe {
                current_syscall_error._type = seL4_InvalidArgument;
                current_syscall_error.invalidArgumentNumber = 0;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
    }
    unsafe {
        if current_extra_caps.excaprefs[0] as usize == 0 {
            debug!("Domain Configure: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let tcap = unsafe { &(*current_extra_caps.excaprefs[0]).cap };
    if unlikely(cap_get_capType(tcap) != cap_thread_cap) {
        debug!("Domain Configure: thread cap required.");
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




#[no_mangle]
pub fn configureIdleThread(_tcb: *const tcb_t) {
    
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
    setRegister(receiver, msgInfoRegister, wordFromMessageInfo(msgInfo));
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

pub fn Arch_initContext() -> arch_tcb_t {
   arch_tcb_t::default()
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
    setRegister(receiver, msgInfoRegister, wordFromMessageInfo(tag));
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
    convert_to_type_ref::<seL4_IPCBuffer>(bufferPtr as usize).get_extra_cptr(i)
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