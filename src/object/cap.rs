use core::mem::{forget, size_of};

use crate::{
    config::{seL4_DeleteFirst, seL4_RevokeFirst},
    kernel::boot::current_syscall_error,
    object::{
        objecttype::finaliseCap,
        structure_gen::{
            cap_null_cap_new, cap_zombie_cap_get_capZombieType, cap_zombie_cap_set_capZombieNumber,
            mdb_node_get_mdbPrev, mdb_node_new,
        },
    },
    println,
    structures::{
        cap_t, cap_tag_t, cte_t, exception_t, finaliseCap_ret, finaliseSlot_ret, mdb_node_t, cap_transfer_t,
    },
};

use super::{
    interrupt::intStateIRQNode,
    objecttype::{
        cap_get_capType, cap_null_cap, cap_zombie_cap, isCapRevocable, sameObjectAs, sameRegionAs,
    },
    structure_gen::{
        cap_endpoint_cap_get_capEPBadge, cap_get_max_free_index, cap_untyped_cap_get_capBlockSize,
        cap_untyped_cap_get_capPtr, cap_untyped_cap_ptr_set_capFreeIndex,
        cap_zombie_cap_get_capZombieNumber, cap_zombie_cap_get_capZombiePtr,
        mdb_node_get_mdbFirstBadged, mdb_node_get_mdbNext, mdb_node_get_mdbRevocable,
        mdb_node_ptr_set_mdbNext, mdb_node_ptr_set_mdbPrev, mdb_node_set_mdbFirstBadged,
        mdb_node_set_mdbPrev, mdb_node_set_mdbRevocable,
    },
};


pub fn ensureNoChildren(slot: *mut cte_t) -> exception_t {
    unsafe {
        if mdb_node_get_mdbNext(&(*slot).cteMDBNode) != 0 {
            let next = mdb_node_get_mdbNext(&(*slot).cteMDBNode) as *mut cte_t;
            if isMDBParentOf(slot, next) {
                unsafe {
                    current_syscall_error._type = seL4_RevokeFirst;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        return exception_t::EXCEPTION_NONE;
    }
}

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
            _ => return true,
        }
    }
}

fn setUntypedCapAsFull(_srcCap: &cap_t, _newCap: &cap_t, _srcSlot: *mut cte_t) {
    unsafe {
        if cap_get_capType(_srcCap) == cap_tag_t::cap_untyped_cap as usize
            && cap_get_capType(_newCap) == cap_tag_t::cap_untyped_cap as usize
        {
            if cap_untyped_cap_get_capPtr(_srcCap) == cap_untyped_cap_get_capPtr(_newCap)
                && cap_untyped_cap_get_capBlockSize(_srcCap)
                    == cap_untyped_cap_get_capBlockSize(_newCap)
            {
                cap_untyped_cap_ptr_set_capFreeIndex(
                    &mut (*_srcSlot).cap,
                    cap_get_max_free_index(_srcCap),
                )
            }
        }
    }
}

pub fn cteInsert(newCap: cap_t, _srcSlot: *mut cte_t, _destSlot: *mut cte_t) {
    unsafe {
        let srcSlot = _srcSlot as *mut cte_t;
        let srcMDB = (*srcSlot).cteMDBNode;
        let srcCap = &(*srcSlot).cap;
        let mut newMDB = srcMDB.clone();
        let newCapIsRevocable: bool = isCapRevocable(&newCap, srcCap);
        mdb_node_set_mdbPrev(&mut newMDB, _srcSlot as usize);
        mdb_node_set_mdbRevocable(newMDB, newCapIsRevocable as usize);
        mdb_node_set_mdbFirstBadged(newMDB, newCapIsRevocable as usize);
        setUntypedCapAsFull(srcCap, &newCap, _srcSlot);
        (*(_destSlot as *mut cte_t)).cap = newCap.clone();
        (*(_destSlot as *mut cte_t)).cteMDBNode = newMDB;
        mdb_node_ptr_set_mdbNext(&mut (*srcSlot).cteMDBNode, _destSlot as usize);
        if mdb_node_get_mdbNext(&newMDB) != 0 {
            let cte_ptr = mdb_node_get_mdbNext(&newMDB) as *mut cte_t;
            mdb_node_ptr_set_mdbPrev(&mut (*cte_ptr).cteMDBNode, _destSlot as usize);
        }
        forget(*_destSlot);
    }
}

pub fn cteMove(_newCap: cap_t, _srcSlot: *mut cte_t, _destSlot: *mut cte_t) {
    unsafe {
        let mut mdb = (*_srcSlot).cteMDBNode;
        /* Haskell error: "cteInsert to non-empty destination" */
        assert!(cap_get_capType(&(*_destSlot).cap) == cap_tag_t::cap_null_cap as usize);
        /* Haskell error: "cteInsert: mdb entry must be empty" */
        assert!(
            mdb_node_get_mdbNext(&(*_destSlot).cteMDBNode) as usize == 0
                && mdb_node_get_mdbPrev(&(*_destSlot).cteMDBNode) as usize == 0
        );
        (*_destSlot).cap = _newCap;
        (*_srcSlot).cap = cap_null_cap_new();
        (*_destSlot).cteMDBNode = mdb;
        (*_srcSlot).cteMDBNode = mdb_node_new(0, 0, 0, 0);
        let prev_ptr = mdb_node_get_mdbPrev(&mut mdb);
        if prev_ptr != 0 {
            mdb_node_ptr_set_mdbNext(
                &mut (*(prev_ptr as *mut cte_t)).cteMDBNode,
                _destSlot as usize,
            );
        }
        let next_ptr = mdb_node_get_mdbNext(&mut mdb);
        if next_ptr != 0 {
            mdb_node_ptr_set_mdbPrev(
                &mut (*(next_ptr as *mut cte_t)).cteMDBNode,
                _destSlot as usize,
            );
        }
        forget(*_destSlot);
        forget(*_srcSlot);
    }
}

pub fn capSwapForDelete(slot1: *mut cte_t, slot2: *mut cte_t) {
    unsafe {
        if *slot1 == *slot2 {
            return;
        }
        let cap1 = (*slot1).cap;
        let cap2 = (*slot2).cap;
        cteSwap(&cap1, slot1, &cap2, slot2);
    }
}

pub fn cteSwap(cap1: &cap_t, slot1: *mut cte_t, cap2: &cap_t, slot2: *mut cte_t) {
    unsafe {
        let mdb1 = (*slot1).cteMDBNode;
        let mdb2 = (*slot2).cteMDBNode;
        (*slot1).cap = cap2.clone();
        (*slot2).cap = cap2.clone();
        let prev_ptr = mdb_node_get_mdbPrev(&mdb1);
        if prev_ptr != 0 {
            mdb_node_ptr_set_mdbNext(&mut (*(prev_ptr as *mut cte_t)).cteMDBNode, slot2 as usize);
        }
        let next_ptr = mdb_node_get_mdbNext(&mdb1);
        if next_ptr != 0 {
            mdb_node_ptr_set_mdbPrev(&mut (*(next_ptr as *mut cte_t)).cteMDBNode, slot2 as usize);
        }
        (*slot1).cteMDBNode = mdb2;
        (*slot2).cteMDBNode = mdb1;
        let prev_ptr = mdb_node_get_mdbPrev(&mdb2);
        if prev_ptr != 0 {
            mdb_node_ptr_set_mdbNext(&mut (*(prev_ptr as *mut cte_t)).cteMDBNode, slot1 as usize);
        }
        let next_ptr = mdb_node_get_mdbNext(&mdb2);
        if next_ptr != 0 {
            mdb_node_ptr_set_mdbPrev(&mut (*(next_ptr as *mut cte_t)).cteMDBNode, slot1 as usize);
        }
    }
}

pub fn cteDelete(slot: *mut cte_t, exposed: bool) -> exception_t {
    let fs_ret = finaliseSlot(slot, exposed);
    if fs_ret.status != exception_t::EXCEPTION_NONE {
        return fs_ret.status;
    }

    if exposed || fs_ret.success {
        emptySlot(slot, fs_ret.cleanupInfo);
    }
    return exception_t::EXCEPTION_NONE;
}

pub fn emptySlot(slot: *mut cte_t, _cleanupInfo: cap_t) {
    unsafe {
        if cap_get_capType(&(*slot).cap) != cap_null_cap {
            let mdbNode = (*slot).cteMDBNode;
            let prev = mdb_node_get_mdbPrev(&mdbNode);
            let next = mdb_node_get_mdbNext(&mdbNode);
            if prev != 0 {
                let prev_ptr = mdb_node_get_mdbPrev(&mdbNode) as *mut cte_t;
                mdb_node_ptr_set_mdbNext(&mut (*prev_ptr).cteMDBNode, next);
            }
            if next != 0 {
                let next_ptr = mdb_node_get_mdbNext(&mdbNode) as *mut cte_t;
                mdb_node_ptr_set_mdbPrev(&mut (*next_ptr).cteMDBNode, prev);
            }
            (*slot).cap = cap_null_cap_new();
            (*slot).cteMDBNode = mdb_node_t::default();
        }
    }
}

pub fn isFinalcapability(cte: *mut cte_t) -> bool {
    unsafe {
        let mdb = (*cte).cteMDBNode;
        let prevIsSameObject: bool;
        if mdb_node_get_mdbPrev(&mdb) == 0 {
            prevIsSameObject = false;
        } else {
            let prev = mdb_node_get_mdbPrev(&mdb) as *mut cte_t;
            prevIsSameObject = sameObjectAs(&(*prev).cap, &(*cte).cap);
        }
        if prevIsSameObject {
            false
        } else {
            if mdb_node_get_mdbNext(&mdb) != 0 {
                true
            } else {
                let next = mdb_node_get_mdbPrev(&mdb) as *const cte_t;
                return !sameObjectAs(&(*cte).cap, &(*next).cap);
            }
        }
    }
}

#[inline]
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
pub fn capCyclicZombie(cap: &cap_t, slot: *mut cte_t) -> bool {
    let ptr = cap_zombie_cap_get_capZombiePtr(cap) as *mut cte_t;
    return cap_get_capType(cap) == cap_zombie_cap && ptr == slot;
}

pub fn finaliseSlot(slot: *mut cte_t, immediate: bool) -> finaliseSlot_ret {
    unsafe {
        let mut _final: bool;
        let mut fc_ret: finaliseCap_ret;
        let mut ret = finaliseSlot_ret::default();
        let mut status: exception_t;

        while cap_get_capType(&(*slot).cap) != cap_null_cap {
            _final = isFinalcapability(slot);
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
        }
        ret.status = exception_t::EXCEPTION_NONE;
        ret.success = true;
        ret.cleanupInfo = cap_null_cap_new();
        return ret;
    }
}

pub fn cteRevoke(slot: *mut cte_t) -> exception_t {
    unsafe {
        let mut next = mdb_node_get_mdbNext(&(*slot).cteMDBNode);
        if next != 0 {
            let mut nextPtr = mdb_node_get_mdbNext(&(*slot).cteMDBNode) as *mut cte_t;
            while next != 0 && isMDBParentOf(slot, nextPtr) {
                let status = cteDelete(nextPtr, true);
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
                        cap_zombie_cap_set_capZombieNumber(&mut (*slot).cap, n - 1);
                    }
                }
                _ => {}
            }
        } else {
            assert!(ptr != slot);
            if cap_get_capType(&(*ptr).cap) != cap_zombie_cap {
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

pub fn cteDeleteOne(slot: *mut cte_t) {
    unsafe {
        let cap_type = cap_get_capType(&(*slot).cap);
        if cap_type != cap_null_cap {
            let _final = isFinalcapability(slot);
            let fc_ret = finaliseCap(&(*slot).cap, _final, true);
            assert!(
                capRemovable(&fc_ret.remainder, slot)
                    && cap_get_capType(&fc_ret.cleanupInfo) == cap_null_cap
            );
            emptySlot(slot, cap_null_cap_new());
        }
    }
}

pub fn ensureEmptySlot(slot: *mut cte_t) -> exception_t {
    unsafe {
        if cap_get_capType(&(*slot).cap) != cap_null_cap {
            unsafe {
                current_syscall_error._type = seL4_DeleteFirst;
            }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    exception_t::EXCEPTION_NONE
}

