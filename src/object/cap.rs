use crate::{
    kernel::{
        boot::{current_extra_caps, current_lookup_fault, current_syscall_error},
        cspace::{rust_lookupPivotSlot, rust_lookupSourceSlot, rust_lookupTargetSlot},
    },
    syscall::getSyscallArg,
};

use common::message_info::*;

use super::{
    endpoint::cancelBadgedSends,
    interrupt::intStateIRQNode,
    objecttype::{hasCancelSendRight, maskCapRights},
};
use task_manager::*;
use ipc::*;
use common::{structures::{exception_t, lookup_fault_missing_capability_new}, sel4_config::*};
use cspace::interface::*;
use log::debug;

pub fn deletingIRQHandler(irq: usize) {
    unsafe {
        let slot = (intStateIRQNode + irq) as *mut cte_t;
        cteDeleteOne(slot);
    }
}

#[no_mangle]
pub fn ensureEmptySlot(slot: *mut cte_t) -> exception_t {
    unsafe {
        if cap_get_capType(&(*slot).cap) != cap_null_cap {
            current_syscall_error._type = seL4_DeleteFirst;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    exception_t::EXCEPTION_NONE
}


#[no_mangle]
pub fn invokeCNodeSaveCaller(destSlot: *mut cte_t) -> exception_t {
    let srcSlot = unsafe { getCSpace(ksCurThread as usize, tcbCaller) };
    let cap = unsafe { &(*srcSlot).cap };
    match cap_get_capType(cap) {
        cap_null_cap => {
            debug!("CNode SaveCaller: Reply cap not present.");
        }
        cap_reply_cap => {
            if cap_reply_cap_get_capReplyMaster(cap) == 0 {
                cteMove(cap, srcSlot, destSlot);
            }
        }
        _ => panic!("caller capability must be null or reply"),
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn invokeCNodeRotate(
    cap1: &cap_t,
    cap2: &cap_t,
    slot1: *mut cte_t,
    slot2: *mut cte_t,
    slot3: *mut cte_t,
) -> exception_t {
    if slot1 == slot3 {
        cteSwap(cap1, slot1, cap2, slot2);
    } else {
        cteMove(cap2, slot2, slot3);
        cteMove(cap1, slot1, slot2);
    }
    return exception_t::EXCEPTION_NONE;
}

#[no_mangle]
pub fn invokeCNodeMove(cap: &cap_t, srcSlot: *mut cte_t, destSlot: *mut cte_t) -> exception_t {
    cteMove(cap, srcSlot, destSlot);
    return exception_t::EXCEPTION_NONE;
}

#[no_mangle]
pub fn invokeCNodeInsert(cap: &cap_t, srcSlot: *mut cte_t, destSlot: *mut cte_t) -> exception_t {
    cteInsert(cap, srcSlot, destSlot);
    return exception_t::EXCEPTION_NONE;
}

#[no_mangle]
pub fn invokeCNodeCancelBadgedSends(cap: &cap_t) -> exception_t {
    let badge = cap_endpoint_cap_get_capEPBadge(cap);
    if badge != 0 {
        let ep = cap_endpoint_cap_get_capEPPtr(cap) as *mut endpoint_t;
        cancelBadgedSends(ep, badge);
    }
    return exception_t::EXCEPTION_NONE;
}

#[no_mangle]
pub fn invokeCNodeRevoke(destSlot: *mut cte_t) -> exception_t {
    cteRevoke(destSlot)
}

#[no_mangle]
pub fn invokeCNodeDelete(destSlot: *mut cte_t) -> exception_t {
    cteDelete(destSlot, true)
}

#[no_mangle]
pub fn decodeCNodeInvocation(
    invLabel: MessageLabel,
    length: usize,
    cap: &cap_t,
    buffer: *mut usize,
) -> exception_t {
    if invLabel < MessageLabel::CNodeRevoke || invLabel > MessageLabel::CNodeSaveCaller {
        debug!("CNodeCap: Illegal Operation attempted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if length < 2 {
        debug!("CNode operation: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let index = getSyscallArg(0, buffer);
    let w_bits = getSyscallArg(1, buffer);
    let lu_ret = rust_lookupTargetSlot(cap, index, w_bits);
    let destSlot = lu_ret.slot;
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        debug!("CNode operation: Target slot invalid.");
        return lu_ret.status;
    }
    if invLabel >= MessageLabel::CNodeCopy && invLabel <= MessageLabel::CNodeMutate {
        unsafe {
            if length < 4 || current_extra_caps.excaprefs[0] as usize == 0 {
                debug!("CNode Copy/Mint/Move/Mutate: Truncated message.");
                current_syscall_error._type = seL4_TruncatedMessage;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        let srcIndex = getSyscallArg(2, buffer);
        let srcDepth = getSyscallArg(3, buffer);
        let srcRoot: &cap_t;
        unsafe {
            srcRoot = &(*current_extra_caps.excaprefs[0]).cap;
        }
        let status = ensureEmptySlot(destSlot);
        if status != exception_t::EXCEPTION_NONE {
            debug!("CNode Copy/Mint/Move/Mutate: Destination not empty.");
            return status;
        }
        let lu_ret = rust_lookupSourceSlot(srcRoot, srcIndex, srcDepth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            debug!("CNode Copy/Mint/Move/Mutate: Invalid source slot.");
            return status;
        }
        let srcSlot = lu_ret.slot;
        unsafe {
            if cap_get_capType(&(*srcSlot).cap) == cap_null_cap {
                debug!("CNode Copy/Mint/Move/Mutate: Source slot invalid or empty.");
                current_syscall_error._type = seL4_FailedLookup;
                current_syscall_error.failedLookupWasSource = 1;
                current_lookup_fault = lookup_fault_missing_capability_new(srcDepth);
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        let newCap: &cap_t;
        let srcCap: &cap_t;
        let newCap1: cap_t;
        let srcCap1: cap_t;

        let isMove: bool;
        match invLabel {
            MessageLabel::CNodeCopy => {
                if length < 5 {
                    debug!("Truncated message for CNode Copy operation.");
                    unsafe {
                        current_syscall_error._type = seL4_TruncatedMessage;
                        return exception_t::EXCEPTION_SYSCALL_ERROR;
                    }
                }
                let cap_rights = rightsFromWord(getSyscallArg(4, buffer));
                unsafe {
                    srcCap1 = maskCapRights(cap_rights, &(*srcSlot).cap);
                    srcCap = &srcCap1;
                    let dc_ret = deriveCap(srcSlot, &srcCap);
                    if dc_ret.status != exception_t::EXCEPTION_NONE {
                        debug!("Error deriving cap for CNode Copy operation.");
                        return dc_ret.status;
                    }
                    newCap1 = dc_ret.cap;
                    newCap = &newCap1;
                    isMove = false;
                }
            }
            MessageLabel::CNodeMint => {
                if length < 6 {
                    debug!("Truncated message for CNode Mint operation.");
                    unsafe {
                        current_syscall_error._type = seL4_TruncatedMessage;
                        return exception_t::EXCEPTION_SYSCALL_ERROR;
                    }
                }
                let cap_rights = rightsFromWord(getSyscallArg(4, buffer));
                let capData = getSyscallArg(5, buffer);
                unsafe {
                    srcCap1 = maskCapRights(cap_rights, &(*srcSlot).cap);
                    srcCap = &srcCap1;
                    let dc_ret = deriveCap(srcSlot, &updateCapData(false, capData, &srcCap));
                    if dc_ret.status != exception_t::EXCEPTION_NONE {
                        debug!("Error deriving cap for CNode Mint operation.");
                        return dc_ret.status;
                    }
                    newCap1 = dc_ret.cap;
                    newCap = &newCap1;
                    isMove = false;
                }
            }
            MessageLabel::CNodeMove => unsafe {
                newCap = &(*srcSlot).cap;
                isMove = true;
            },
            MessageLabel::CNodeMutate => {
                if length < 5 {
                    debug!("Truncated message for CNode Mutate operation.");
                    unsafe {
                        current_syscall_error._type = seL4_TruncatedMessage;
                        return exception_t::EXCEPTION_SYSCALL_ERROR;
                    }
                }
                let capData = getSyscallArg(4, buffer);
                unsafe {
                    newCap1 = updateCapData(true, capData, &(*srcSlot).cap);
                    newCap = &newCap1;
                }
                isMove = true;
            }
            _ => panic!("invalid invLabel:{:?}", invLabel),
        }
        if cap_get_capType(newCap) == cap_null_cap {
            debug!("CNode Copy/Mint/Move/Mutate: Mutated cap would be invalid.");
            unsafe {
                current_syscall_error._type = seL4_IllegalOperation;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }

        unsafe {
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
        }
        if isMove {
            return invokeCNodeMove(newCap, srcSlot, destSlot);
        } else {
            return invokeCNodeInsert(newCap, srcSlot, destSlot);
        }
    }
    if invLabel == MessageLabel::CNodeRevoke {
        unsafe {
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            return invokeCNodeRevoke(destSlot);
        }
    }
    if invLabel == MessageLabel::CNodeDelete {
        unsafe {
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            return invokeCNodeDelete(destSlot);
        }
    }
    if invLabel == MessageLabel::CNodeSaveCaller {
        let status = ensureEmptySlot(destSlot);
        if status != exception_t::EXCEPTION_NONE {
            debug!("CNode SaveCaller: Destination slot not empty.");
            return status;
        }
        unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
        }
        return invokeCNodeSaveCaller(destSlot);
    }
    if invLabel == MessageLabel::CNodeCancelBadgedSends {
        unsafe {
            let destCap = &(*destSlot).cap;
            if !hasCancelSendRight(destCap) {
                debug!("CNode CancelBadgedSends: Target cap invalid.");
                current_syscall_error._type = seL4_IllegalOperation;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            return invokeCNodeCancelBadgedSends(destCap);
        }
    }
    if invLabel == MessageLabel::CNodeRotate {
        unsafe {
            if length < 8
                || current_extra_caps.excaprefs[0] as usize == 0
                || current_extra_caps.excaprefs[1] as usize == 0
            {
                debug!("CNode Rotate: Target cap invalid.");
                current_syscall_error._type = seL4_TruncatedMessage;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let pivotNewData = getSyscallArg(2, buffer);
            let pivotIndex = getSyscallArg(3, buffer);
            let pivotDepth = getSyscallArg(4, buffer);
            let srcNewData = getSyscallArg(5, buffer);
            let srcIndex = getSyscallArg(6, buffer);
            let srcDepth = getSyscallArg(7, buffer);

            let pivotRoot: &cap_t;
            let pivotSlot: *mut cte_t;
            let srcRoot: &cap_t;
            let srcSlot: *mut cte_t;

            pivotRoot = &(*current_extra_caps.excaprefs[0]).cap;
            srcRoot = &(*current_extra_caps.excaprefs[1]).cap;
            let mut lu_ret = rust_lookupSourceSlot(srcRoot, srcIndex, srcDepth);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                return lu_ret.status;
            }
            srcSlot = lu_ret.slot as *mut cte_t;
            lu_ret = rust_lookupPivotSlot(pivotRoot, pivotIndex, pivotDepth);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                return lu_ret.status;
            }
            pivotSlot = lu_ret.slot as *mut cte_t;

            if pivotSlot == srcSlot || pivotSlot == destSlot {
                debug!("CNode Rotate: Pivot slot the same as source or dest slot.");
                current_syscall_error._type = seL4_IllegalOperation;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            if srcSlot != destSlot {
                let status = ensureEmptySlot(destSlot);
                if status != exception_t::EXCEPTION_NONE {
                    return status;
                }
            }
            if cap_get_capType(&(*srcSlot).cap) == cap_null_cap {
                debug!("CNode Rotate: Target cap invalid.");
                current_syscall_error._type = seL4_FailedLookup;
                current_syscall_error.failedLookupWasSource = 1;
                current_lookup_fault = lookup_fault_missing_capability_new(srcDepth);
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            if cap_get_capType(&(*pivotSlot).cap) == cap_null_cap {
                debug!("CNode Rotate: Target cap invalid.");
                current_syscall_error._type = seL4_FailedLookup;
                current_syscall_error.failedLookupWasSource = 0;
                current_lookup_fault = lookup_fault_missing_capability_new(pivotDepth);
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let newSrcCap = updateCapData(true, srcNewData, &(*srcSlot).cap);
            let newPivot = updateCapData(true, pivotNewData, &(*pivotSlot).cap);
            if cap_get_capType(&newSrcCap) == cap_null_cap {
                debug!("CNode Rotate: Source cap invalid");
                current_syscall_error._type = seL4_IllegalOperation;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            if cap_get_capType(&newPivot) == cap_null_cap {
                debug!("CNode Rotate: Pivot cap invalid");
                current_syscall_error._type = seL4_IllegalOperation;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            return invokeCNodeRotate(&newSrcCap, &newPivot, srcSlot, pivotSlot, destSlot);
        }
    }
    exception_t::EXCEPTION_NONE
}
