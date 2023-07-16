use crate::{
    config::{
        seL4_DeleteFirst, seL4_FailedLookup, seL4_IllegalOperation, seL4_RevokeFirst,
        seL4_TruncatedMessage, tcbCaller, CNodeCancelBadgedSends, CNodeCopy, CNodeDelete,
        CNodeMint, CNodeMove, CNodeMutate, CNodeRevoke, CNodeRotate, CNodeSaveCaller,
        ThreadStateRestart,
    },
    kernel::{
        boot::{current_extra_caps, current_lookup_fault, current_syscall_error},
        cspace::{rust_lookupPivotSlot, rust_lookupSourceSlot, rust_lookupTargetSlot},
        preemption::preemptionPoint,
        thread::{getCSpace, ksCurThread, setThreadState},
        transfermsg::rightsFromWord,
    },
    object::{
        objecttype::finaliseCap,
        structure_gen::{
            cap_zombie_cap_get_capZombieType, cap_zombie_cap_set_capZombieNumber,
            lookup_fault_missing_capability_new
        },
    },
    println,
    structures::{endpoint_t, exception_t, finaliseCap_ret, finaliseSlot_ret, tcb_t},
    syscall::getSyscallArg,
    utils::MAX_FREE_INDEX, cspace::{cap::cap_t, cte_t},
};

use super::{
    endpoint::cancelBadgedSends,
    interrupt::intStateIRQNode,
    objecttype::{deriveCap, hasCancelSendRight, isCapRevocable, maskCapRights, postCapDeletion, sameObjectAs,
        sameRegionAs, updateCapData,
    },
    structure_gen::{
        cap_endpoint_cap_get_capEPBadge, cap_endpoint_cap_get_capEPPtr,
        cap_notification_cap_get_capNtfnBadge, cap_reply_cap_get_capReplyMaster, cap_zombie_cap_get_capZombieNumber,
        cap_zombie_cap_get_capZombiePtr
    },
};

use crate::cspace::interface::*;

#[no_mangle]
pub fn ensureNoChildren(slot: *mut cte_t) -> exception_t {
    unsafe {
        if mdb_node_get_mdbNext(&(*slot).cteMDBNode) != 0 {
            let next = mdb_node_get_mdbNext(&(*slot).cteMDBNode) as *mut cte_t;
            if isMDBParentOf(slot, next) {
                current_syscall_error._type = seL4_RevokeFirst;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        return exception_t::EXCEPTION_NONE;
    }
}

#[no_mangle]
fn isMDBParentOf(cte1: *mut cte_t, cte2: *mut cte_t) -> bool {
    unsafe {
        if !(mdb_node_get_mdbRevocable(&(*cte1).cteMDBNode) != 0) {
            return false;
        }
        if !sameRegionAs(&(*cte1).cap, &(*cte2).cap) {
            return false;
        }
        match cap_get_capType(&(*cte1).cap) {
            cap_endpoint_cap => {
                let badge: usize;
                badge = cap_endpoint_cap_get_capEPBadge(&(*cte1).cap);
                if badge == 0 {
                    return true;
                }
                return badge == cap_endpoint_cap_get_capEPBadge(&(*cte2).cap)
                    && !(mdb_node_get_mdbFirstBadged(&(*cte2).cteMDBNode) != 0);
            }
            cap_notification_cap => {
                let badge = cap_notification_cap_get_capNtfnBadge(&(*cte1).cap);
                if badge == 0 {
                    return true;
                }
                return (badge == cap_notification_cap_get_capNtfnBadge(&(*cte2).cap))
                    && (mdb_node_get_mdbFirstBadged(&(*cte2).cteMDBNode) != 0);
            }
            _ => return true,
        }
    }
}

fn setUntypedCapAsFull(_srcCap: &cap_t, _newCap: &cap_t, srcSlot: *mut cte_t) {
    unsafe {
        if cap_get_capType(_srcCap) == cap_untyped_cap
            && cap_get_capType(_newCap) == cap_untyped_cap
        {
            if (cap_untyped_cap_get_capPtr(_srcCap) == cap_untyped_cap_get_capPtr(_newCap))
                && (cap_untyped_cap_get_capBlockSize(_srcCap)
                    == cap_untyped_cap_get_capBlockSize(_newCap))
            {
                cap_untyped_cap_ptr_set_capFreeIndex(
                    &mut (*srcSlot).cap,
                    MAX_FREE_INDEX(cap_untyped_cap_get_capBlockSize(_srcCap)),
                );
            }
        }
    }
}

#[no_mangle]
pub fn cteInsert(newCap: &cap_t, srcSlot: *mut cte_t, destSlot: *mut cte_t) {
    unsafe {
        let srcMDB = &mut (*srcSlot).cteMDBNode;
        let srcCap = &(*srcSlot).cap;
        let mut newMDB = srcMDB.clone();
        let newCapIsRevocable: bool = isCapRevocable(newCap, srcCap);
        mdb_node_set_mdbPrev(&mut newMDB, srcSlot as usize);
        mdb_node_set_mdbRevocable(&mut newMDB, newCapIsRevocable as usize);
        mdb_node_set_mdbFirstBadged(&mut newMDB, newCapIsRevocable as usize);

        /* Haskell error: "cteInsert to non-empty destination" */
        assert!(cap_get_capType(&(*destSlot).cap) == cap_null_cap);
        /* Haskell error: "cteInsert: mdb entry must be empty" */
        assert!(
            mdb_node_get_mdbNext(&(*destSlot).cteMDBNode) == 0
                && mdb_node_get_mdbPrev(&(*destSlot).cteMDBNode) == 0,
        );

        setUntypedCapAsFull(srcCap, newCap, srcSlot);
        (*destSlot).cap = newCap.clone();
        (*destSlot).cteMDBNode = newMDB;
        mdb_node_ptr_set_mdbNext(&mut (*srcSlot).cteMDBNode, destSlot as usize);
        if mdb_node_get_mdbNext(&newMDB) != 0 {
            let cte_ptr = mdb_node_get_mdbNext(&newMDB) as *mut cte_t;
            mdb_node_ptr_set_mdbPrev(&mut (*cte_ptr).cteMDBNode, destSlot as usize);
        }
    }
}

#[no_mangle]
pub fn cteMove(_newCap: &cap_t, srcSlot: *mut cte_t, destSlot: *mut cte_t) {
    unsafe {
        /* Haskell error: "cteInsert to non-empty destination" */
        assert!(cap_get_capType(&(*destSlot).cap) == cap_null_cap);
        /* Haskell error: "cteInsert: mdb entry must be empty" */
        assert!(
            mdb_node_get_mdbNext(&(*destSlot).cteMDBNode) as usize == 0
                && mdb_node_get_mdbPrev(&(*destSlot).cteMDBNode) as usize == 0
        );
        let mut mdb = (*srcSlot).cteMDBNode;
        (*destSlot).cap = _newCap.clone();
        (*srcSlot).cap = cap_null_cap_new();
        (*destSlot).cteMDBNode = mdb;
        (*srcSlot).cteMDBNode = mdb_node_new(0, 0, 0, 0);

        let prev_ptr = mdb_node_get_mdbPrev(&mut mdb);
        if prev_ptr != 0 {
            mdb_node_ptr_set_mdbNext(
                &mut (*(prev_ptr as *mut cte_t)).cteMDBNode,
                destSlot as usize,
            );
        }
        let next_ptr = mdb_node_get_mdbNext(&mut mdb);
        if next_ptr != 0 {
            mdb_node_ptr_set_mdbPrev(
                &mut (*(next_ptr as *mut cte_t)).cteMDBNode,
                destSlot as usize,
            );
        }
    }
}

#[no_mangle]
pub fn capSwapForDelete(slot1: *mut cte_t, slot2: *mut cte_t) {
    unsafe {
        if slot1 == slot2 {
            return;
        }
        let cap1 = &(*slot1).cap;
        let cap2 = &(*slot2).cap;
        cteSwap(cap1, slot1, cap2, slot2);
    }
}

#[no_mangle]
pub fn cteSwap(cap1: &cap_t, slot1: *mut cte_t, cap2: &cap_t, slot2: *mut cte_t) {
    unsafe {
        let mdb1 = (*slot1).cteMDBNode;
        let mdb2 = (*slot2).cteMDBNode;
        {
            let prev_ptr = mdb_node_get_mdbPrev(&mdb1);
            if prev_ptr != 0 {
                mdb_node_ptr_set_mdbNext(
                    &mut (*(prev_ptr as *mut cte_t)).cteMDBNode,
                    slot2 as usize,
                );
            }
            let next_ptr = mdb_node_get_mdbNext(&mdb1);
            if next_ptr != 0 {
                mdb_node_ptr_set_mdbPrev(
                    &mut (*(next_ptr as *mut cte_t)).cteMDBNode,
                    slot2 as usize,
                );
            }
        }
        let val1 = cap1.words[0];
        let val2 = cap1.words[1];
        (*slot1).cap = cap2.clone();
        //FIXME::result not right due to compiler

        (*slot2).cap = cap_t {
            words: [val1, val2],
        };
        (*slot1).cteMDBNode = mdb2;
        (*slot2).cteMDBNode = mdb1;
        {
            let prev_ptr = mdb_node_get_mdbPrev(&mdb2);
            if prev_ptr != 0 {
                mdb_node_ptr_set_mdbNext(
                    &mut (*(prev_ptr as *mut cte_t)).cteMDBNode,
                    slot1 as usize,
                );
            }
            let next_ptr = mdb_node_get_mdbNext(&mdb2);
            if next_ptr != 0 {
                mdb_node_ptr_set_mdbPrev(
                    &mut (*(next_ptr as *mut cte_t)).cteMDBNode,
                    slot1 as usize,
                );
            }
        }
    }
}

#[no_mangle]
pub fn cteDelete(slot: *mut cte_t, exposed: bool) -> exception_t {
    let fs_ret = finaliseSlot(slot, exposed);
    if fs_ret.status != exception_t::EXCEPTION_NONE {
        return fs_ret.status;
    }

    if exposed || fs_ret.success {
        emptySlot(slot, &fs_ret.cleanupInfo);
    }
    return exception_t::EXCEPTION_NONE;
}

#[no_mangle]
pub fn emptySlot(slot: *mut cte_t, _cleanupInfo: &cap_t) {
    unsafe {
        if cap_get_capType(&(*slot).cap) != cap_null_cap {
            let mdbNode = &(*slot).cteMDBNode;
            let prev = mdb_node_get_mdbPrev(mdbNode);
            let next = mdb_node_get_mdbNext(mdbNode);
            if prev != 0 {
                let prev_ptr = mdb_node_get_mdbPrev(mdbNode) as *mut cte_t;
                mdb_node_ptr_set_mdbNext(&mut (*prev_ptr).cteMDBNode, next);
            }
            if next != 0 {
                let next_ptr = mdb_node_get_mdbNext(mdbNode) as *mut cte_t;
                mdb_node_ptr_set_mdbPrev(&mut (*next_ptr).cteMDBNode, prev);
                mdb_node_set_mdbFirstBadged(
                    &mut (*next_ptr).cteMDBNode,
                    ((mdb_node_get_mdbFirstBadged(&(*next_ptr).cteMDBNode) != 0)
                        || (mdb_node_get_mdbFirstBadged(mdbNode) != 0))
                        as usize,
                );
            }
            (*slot).cap = cap_null_cap_new();
            (*slot).cteMDBNode = mdb_node_new(0, 0, 0, 0);

            postCapDeletion(_cleanupInfo);
        }
    }
}

#[no_mangle]
pub fn isFinalCapability(cte: *mut cte_t) -> bool {
    unsafe {
        let mdb = &(*cte).cteMDBNode;
        let prevIsSameObject: bool;
        if mdb_node_get_mdbPrev(mdb) == 0 {
            prevIsSameObject = false;
        } else {
            let prev = mdb_node_get_mdbPrev(mdb) as *mut cte_t;
            prevIsSameObject = sameObjectAs(&(*prev).cap, &(*cte).cap);
        }
        if prevIsSameObject {
            false
        } else {
            if mdb_node_get_mdbNext(mdb) == 0 {
                true
            } else {
                let next = mdb_node_get_mdbNext(&mdb) as *mut cte_t;
                return !sameObjectAs(&(*cte).cap, &(*next).cap);
            }
        }
    }
}

#[inline]
#[no_mangle]
fn capRemovable(cap: &cap_t, slot: *mut cte_t) -> bool {
    match cap_get_capType(cap) {
        cap_null_cap => {
            return true;
        }
        cap_zombie_cap => {
            let n = cap_zombie_cap_get_capZombieNumber(cap);
            let ptr = cap_zombie_cap_get_capZombiePtr(cap);
            let z_slot = ptr as *mut cte_t;
            return n == 0 || (n == 1 && slot == z_slot);
        }
        _ => {
            panic!("Invalid cap type , finaliseCap should only return Zombie or NullCap");
        }
    }
}

#[inline]
#[no_mangle]
pub fn capCyclicZombie(cap: &cap_t, slot: *mut cte_t) -> bool {
    let ptr = cap_zombie_cap_get_capZombiePtr(cap) as *mut cte_t;
    (cap_get_capType(cap) == cap_zombie_cap) && (ptr == slot)
}

#[no_mangle]
pub fn finaliseSlot(slot: *mut cte_t, immediate: bool) -> finaliseSlot_ret {
    unsafe {
        let mut _final: bool;
        let mut fc_ret: finaliseCap_ret;
        let mut ret = finaliseSlot_ret::default();
        let mut status: exception_t;

        while cap_get_capType(&(*slot).cap) != cap_null_cap {
            _final = isFinalCapability(slot);
            fc_ret = finaliseCap(&(*slot).cap, _final, false);
            let flag = capRemovable(&fc_ret.remainder, slot);
            if flag {
                ret.status = exception_t::EXCEPTION_NONE;
                ret.success = true;
                ret.cleanupInfo = fc_ret.cleanupInfo;
                return ret;
            }
            (*slot).cap = fc_ret.remainder;
            if !immediate && capCyclicZombie(&(*slot).cap, slot) {
                ret.status = exception_t::EXCEPTION_NONE;
                ret.success = false;
                ret.cleanupInfo = fc_ret.cleanupInfo;
                return ret;
            }
            status = reduceZombie(slot, immediate);
            if status != exception_t::EXCEPTION_NONE {
                ret.status = status;
                ret.success = false;
                ret.cleanupInfo = cap_null_cap_new();
                return ret;
            }
            //TODO::preemptionPoint();
            let status = preemptionPoint();
            if status != exception_t::EXCEPTION_NONE {
                ret.status = status;
                ret.success = false;
                ret.cleanupInfo = cap_null_cap_new();
                return ret;
            }
        }
        ret.status = exception_t::EXCEPTION_NONE;
        ret.success = true;
        ret.cleanupInfo = cap_null_cap_new();
        return ret;
    }
}

#[no_mangle]
pub fn cteRevoke(slot: *mut cte_t) -> exception_t {
    unsafe {
        let mut next = mdb_node_get_mdbNext(&(*slot).cteMDBNode);
        if next != 0 {
            let mut nextPtr = mdb_node_get_mdbNext(&(*slot).cteMDBNode) as *mut cte_t;
            while next != 0 && isMDBParentOf(slot, nextPtr) {
                let mut status = cteDelete(nextPtr, true);
                if status != exception_t::EXCEPTION_NONE {
                    return status;
                }
                status = preemptionPoint();
                if status != exception_t::EXCEPTION_NONE {
                    return status;
                }

                next = mdb_node_get_mdbNext(&(*slot).cteMDBNode);
                if next == 0 {
                    break;
                }
                nextPtr = mdb_node_get_mdbNext(&(*slot).cteMDBNode) as *mut cte_t;
            }
        }
    }
    return exception_t::EXCEPTION_NONE;
}

#[no_mangle]
pub fn reduceZombie(slot: *mut cte_t, immediate: bool) -> exception_t {
    unsafe {
        assert!(cap_get_capType(&(*slot).cap) == cap_zombie_cap);
        let status: exception_t;
        let ptr = cap_zombie_cap_get_capZombiePtr(&(*slot).cap) as *mut cte_t;
        let n = cap_zombie_cap_get_capZombieNumber(&(*slot).cap);
        let _type = cap_zombie_cap_get_capZombieType(&(*slot).cap);
        assert!(n > 0);
        if immediate {
            let endSlot = (cap_zombie_cap_get_capZombiePtr(&(*slot).cap) as *mut cte_t).add(n - 1);
            status = cteDelete(endSlot, false);
            if status != exception_t::EXCEPTION_NONE {
                return status;
            }
            match cap_get_capType(&(*slot).cap) {
                cap_null_cap => {
                    return exception_t::EXCEPTION_NONE;
                }
                cap_zombie_cap => {
                    let ptr2 = cap_zombie_cap_get_capZombiePtr(&(*slot).cap) as *mut cte_t;
                    if ptr == ptr2
                        && cap_zombie_cap_get_capZombieNumber(&(*slot).cap) == n
                        && cap_zombie_cap_get_capZombieType(&(*slot).cap) == _type
                    {
                        assert!(cap_get_capType(&(*endSlot).cap) == cap_null_cap);
                        cap_zombie_cap_set_capZombieNumber(&mut (*slot).cap, n - 1);
                    } else {
                        assert!(ptr2 == slot && ptr != slot);
                    }
                }
                _ => panic!("Expected recursion to result in Zombie."),
            }
        } else {
            assert!(ptr != slot);
            if cap_get_capType(&(*ptr).cap) == cap_zombie_cap {
                let ptr1 = cap_zombie_cap_get_capZombiePtr(&(*ptr).cap) as *mut cte_t;
                assert!(ptr != ptr1);
            }
            capSwapForDelete(ptr, slot);
        }
    }
    return exception_t::EXCEPTION_NONE;
}

pub fn deletingIRQHandler(irq: usize) {
    unsafe {
        let slot = (intStateIRQNode + irq) as *mut cte_t;
        cteDeleteOne(slot);
    }
}

#[no_mangle]
pub fn cteDeleteOne(slot: *mut cte_t) {
    unsafe {
        let cap_type = cap_get_capType(&(*slot).cap);
        if cap_type != cap_null_cap {
            let _final = isFinalCapability(slot);
            let fc_ret = finaliseCap(&(*slot).cap, _final, true);
            assert!(
                capRemovable(&fc_ret.remainder, slot)
                    && cap_get_capType(&fc_ret.cleanupInfo) == cap_null_cap
            );
            emptySlot(slot, &cap_null_cap_new());
        }
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
pub fn insertNewCap(parent: *mut cte_t, _slot: *mut cte_t, cap: &cap_t) {
    unsafe {
        let next = mdb_node_get_mdbNext(&(*parent).cteMDBNode);
        let mut slot = _slot as *mut cte_t;
        (*slot).cap = cap.clone();
        (*slot).cteMDBNode = mdb_node_new(next as usize, 1usize, 1usize, parent as usize);
        if next != 0 {
            let next_ptr = next as *mut cte_t;
            mdb_node_ptr_set_mdbPrev(&mut (*next_ptr).cteMDBNode, _slot as usize);
        }
        mdb_node_ptr_set_mdbNext(&mut (*parent).cteMDBNode, _slot as usize);
    }
}

#[no_mangle]
pub fn slotCapLongRunningDelete(slot: *mut cte_t) -> bool {
    unsafe {
        if cap_get_capType(&(*slot).cap) == cap_null_cap {
            return false;
        } else if !isFinalCapability(slot) {
            return false;
        }

        match cap_get_capType(&(*slot).cap) {
            cap_thread_cap | cap_zombie_cap | cap_cnode_cap => true,
            _ => false,
        }
    }
}

#[no_mangle]
pub fn invokeCNodeSaveCaller(destSlot: *mut cte_t) -> exception_t {
    let srcSlot = unsafe { getCSpace(ksCurThread as usize, tcbCaller) };
    let cap = unsafe { &(*srcSlot).cap };
    match cap_get_capType(cap) {
        cap_null_cap => {
            println!("CNode SaveCaller: Reply cap not present.");
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
    invLabel: usize,
    length: usize,
    cap: &cap_t,
    buffer: *mut usize,
) -> exception_t {
    if invLabel < CNodeRevoke || invLabel > CNodeSaveCaller {
        println!("CNodeCap: Illegal Operation attempted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if length < 2 {
        println!("CNode operation: Truncated message.");
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
        println!("CNode operation: Target slot invalid.");
        return lu_ret.status;
    }
    if invLabel >= CNodeCopy && invLabel <= CNodeMutate {
        unsafe {
            if length < 4 || current_extra_caps.excaprefs[0] as usize == 0 {
                println!("CNode Copy/Mint/Move/Mutate: Truncated message.");
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
            println!("CNode Copy/Mint/Move/Mutate: Destination not empty.");
            return status;
        }
        let lu_ret = rust_lookupSourceSlot(srcRoot, srcIndex, srcDepth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            println!("CNode Copy/Mint/Move/Mutate: Invalid source slot.");
            return status;
        }
        let srcSlot = lu_ret.slot;
        unsafe {
            if cap_get_capType(&(*srcSlot).cap) == cap_null_cap {
                println!("CNode Copy/Mint/Move/Mutate: Source slot invalid or empty.");
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
            CNodeCopy => {
                if length < 5 {
                    println!("Truncated message for CNode Copy operation.");
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
                        println!("Error deriving cap for CNode Copy operation.");
                        return dc_ret.status;
                    }
                    newCap1 = dc_ret.cap;
                    newCap = &newCap1;
                    isMove = false;
                }
            }
            CNodeMint => {
                if length < 6 {
                    println!("Truncated message for CNode Mint operation.");
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
                        println!("Error deriving cap for CNode Mint operation.");
                        return dc_ret.status;
                    }
                    newCap1 = dc_ret.cap;
                    newCap = &newCap1;
                    isMove = false;
                }
            }
            CNodeMove => unsafe {
                newCap = &(*srcSlot).cap;
                isMove = true;
            },
            CNodeMutate => {
                if length < 5 {
                    println!("Truncated message for CNode Mutate operation.");
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
            _ => panic!("invalid invLabel:{}", invLabel),
        }
        if cap_get_capType(newCap) == cap_null_cap {
            println!("CNode Copy/Mint/Move/Mutate: Mutated cap would be invalid.");
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
    if invLabel == CNodeRevoke {
        unsafe {
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            return invokeCNodeRevoke(destSlot);
        }
    }
    if invLabel == CNodeDelete {
        unsafe {
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            return invokeCNodeDelete(destSlot);
        }
    }
    if invLabel == CNodeSaveCaller {
        let status = ensureEmptySlot(destSlot);
        if status != exception_t::EXCEPTION_NONE {
            println!("CNode SaveCaller: Destination slot not empty.");
            return status;
        }
        unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
        }
        return invokeCNodeSaveCaller(destSlot);
    }
    if invLabel == CNodeCancelBadgedSends {
        unsafe {
            let destCap = &(*destSlot).cap;
            if !hasCancelSendRight(destCap) {
                println!("CNode CancelBadgedSends: Target cap invalid.");
                current_syscall_error._type = seL4_IllegalOperation;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            return invokeCNodeCancelBadgedSends(destCap);
        }
    }
    if invLabel == CNodeRotate {
        unsafe {
            if length < 8
                || current_extra_caps.excaprefs[0] as usize == 0
                || current_extra_caps.excaprefs[1] as usize == 0
            {
                println!("CNode Rotate: Target cap invalid.");
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
                println!("CNode Rotate: Pivot slot the same as source or dest slot.");
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
                println!("CNode Rotate: Target cap invalid.");
                current_syscall_error._type = seL4_FailedLookup;
                current_syscall_error.failedLookupWasSource = 1;
                current_lookup_fault = lookup_fault_missing_capability_new(srcDepth);
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            if cap_get_capType(&(*pivotSlot).cap) == cap_null_cap {
                println!("CNode Rotate: Target cap invalid.");
                current_syscall_error._type = seL4_FailedLookup;
                current_syscall_error.failedLookupWasSource = 0;
                current_lookup_fault = lookup_fault_missing_capability_new(pivotDepth);
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let newSrcCap = updateCapData(true, srcNewData, &(*srcSlot).cap);
            let newPivot = updateCapData(true, pivotNewData, &(*pivotSlot).cap);
            if cap_get_capType(&newSrcCap) == cap_null_cap {
                println!("CNode Rotate: Source cap invalid");
                current_syscall_error._type = seL4_IllegalOperation;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            if cap_get_capType(&newPivot) == cap_null_cap {
                println!("CNode Rotate: Pivot cap invalid");
                current_syscall_error._type = seL4_IllegalOperation;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
            return invokeCNodeRotate(&newSrcCap, &newPivot, srcSlot, pivotSlot, destSlot);
        }
    }
    exception_t::EXCEPTION_NONE
}
