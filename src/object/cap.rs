use crate::structures::{cap_t, cap_tag_t, cte_t, exception_t};

use super::{
    objecttype::{cap_get_capType, isCapRevocable, sameRegionAs},
    structure_gen::{
        cap_endpoint_cap_get_capEPBadge, cap_get_max_free_index, cap_untyped_cap_get_capBlockSize,
        cap_untyped_cap_get_capPtr, cap_untyped_cap_ptr_set_capFreeIndex,
        mdb_node_get_mdbFirstBadged, mdb_node_get_mdbNext, mdb_node_get_mdbRevocable,
        mdb_node_set_mdbFirstBadged, mdb_node_set_mdbPrev, mdb_node_set_mdbRevocable, mdb_node_ptr_set_mdbNext, mdb_node_ptr_set_mdbPrev,
    },
};

pub fn ensureNoChildren(slot: *const cte_t) -> exception_t {
    unsafe {
        if mdb_node_get_mdbNext(&(*slot).cteMDBNode) != 0 {
            let next = mdb_node_get_mdbNext(&(*slot).cteMDBNode) as *const cte_t;
            if isMDBParentOf(slot, next) {
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        return exception_t::EXCEPTION_NONE;
    }
}

fn isMDBParentOf(cte1: *const cte_t, cte2: *const cte_t) -> bool {
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

pub fn cteInsert(newCap: &cap_t, _srcSlot: *mut cte_t, _destSlot: *mut cte_t) {
    unsafe {
        let srcSlot = _srcSlot as *mut cte_t;
        let srcMDB = (*srcSlot).cteMDBNode;
        let srcCap = &(*srcSlot).cap;
        let mut newMDB = srcMDB.clone();
        let newCapIsRevocable: bool = isCapRevocable(newCap, srcCap);
        mdb_node_set_mdbPrev(&mut newMDB, _srcSlot as usize);
        mdb_node_set_mdbRevocable(newMDB, newCapIsRevocable as usize);
        mdb_node_set_mdbFirstBadged(newMDB, newCapIsRevocable as usize);
        setUntypedCapAsFull(srcCap, newCap, _srcSlot);
        (*(_destSlot as *mut cte_t)).cap = newCap.clone();
        (*(_destSlot as *mut cte_t)).cteMDBNode = newMDB;

        mdb_node_ptr_set_mdbNext(&mut (*srcSlot).cteMDBNode, _destSlot as usize);
        if mdb_node_get_mdbNext(&newMDB) != 0 {
            let cte_ptr = mdb_node_get_mdbNext(&newMDB) as *mut cte_t;
            mdb_node_ptr_set_mdbPrev(
                &mut (*cte_ptr).cteMDBNode ,
                _destSlot as usize,
            );
        }
    }
}
