pub mod cap;
mod cte;
mod mdb;
pub mod interface;

pub use cte::cte_t;
pub use mdb::mdb_node_t;

use crate::utils::{convert_to_mut_type_ref, MAX_FREE_INDEX};

use self::cap::{cap_t, is_cap_revocable, CapTag};

pub fn cte_insert(newCap: &cap_t, srcSlot: &mut cte_t, destSlot: &mut cte_t) {
    let srcMDB = &mut srcSlot.cteMDBNode;
    let srcCap = &(srcSlot.cap.clone());
    let mut newMDB = srcMDB.clone();
    let newCapIsRevocable = is_cap_revocable(newCap, srcCap);
    newMDB.set_prev(srcSlot as *const cte_t as usize);
    newMDB.set_revocable(newCapIsRevocable as usize);
    newMDB.set_first_badged(newCapIsRevocable as usize);

    /* Haskell error: "cteInsert to non-empty destination" */
    assert_eq!(destSlot.cap.get_cap_type(), CapTag::CapNullCap);
    /* Haskell error: "cteInsert: mdb entry must be empty" */
    assert!(destSlot.cteMDBNode.get_next() == 0 && destSlot.cteMDBNode.get_prev() == 0);

    setUntypedCapAsFull(srcCap, newCap, srcSlot);
    
    (*destSlot).cap = newCap.clone();
    (*destSlot).cteMDBNode = newMDB;
    srcSlot.cteMDBNode.set_next(destSlot as *const cte_t as usize);
    if newMDB.get_next() != 0 {
        let cte_ref = convert_to_mut_type_ref::<cte_t>(newMDB.get_next());
        cte_ref.cteMDBNode.set_prev(destSlot as *const cte_t as usize);
    }
}

#[no_mangle]
pub fn cte_move(newCap: &cap_t, srcSlot: &mut cte_t, destSlot: &mut cte_t) {
    unsafe {
        /* Haskell error: "cteInsert to non-empty destination" */
        assert_eq!(destSlot.cap.get_cap_type(), CapTag::CapNullCap);
        /* Haskell error: "cteInsert: mdb entry must be empty" */
        assert!(
            destSlot.cteMDBNode.get_next() == 0
                && destSlot.cteMDBNode.get_prev() == 0
        );
        let mut mdb = srcSlot.cteMDBNode;
        destSlot.cap = newCap.clone();
        srcSlot.cap = cap_t::new_null_cap();
        destSlot.cteMDBNode = mdb;
        srcSlot.cteMDBNode = mdb_node_t::new(0, 0, 0, 0);

        let prev_ptr = mdb.get_prev();
        if prev_ptr != 0 {
            let prev_ref = convert_to_mut_type_ref::<cte_t>(prev_ptr);
            prev_ref.cteMDBNode.set_next(destSlot as *const cte_t as usize);
        }
        let next_ptr = mdb.get_next();
        if next_ptr != 0 {
            let next_ref = convert_to_mut_type_ref::<cte_t>(next_ptr);
            next_ref.cteMDBNode.set_prev(destSlot as *const cte_t as usize);
        }
    }
}


#[no_mangle]
pub fn cte_swap(cap1: &cap_t, slot1: &mut cte_t, cap2: &cap_t, slot2: &mut cte_t) {
    unsafe {
        let mdb1 = slot1.cteMDBNode;
        let mdb2 = slot2.cteMDBNode;
        {
            let prev_ptr = mdb1.get_prev();
            if prev_ptr != 0 {
                convert_to_mut_type_ref::<cte_t>(prev_ptr).cteMDBNode.set_next(slot2 as *const cte_t as usize);
            }
            let next_ptr = mdb1.get_next();
            if next_ptr != 0 {
                convert_to_mut_type_ref::<cte_t>(next_ptr).cteMDBNode.set_prev(slot2 as *const cte_t as usize);
            }
        }
        let val1 = cap1.words[0];
        let val2 = cap1.words[1];
        slot1.cap = cap2.clone();
        //FIXME::result not right due to compiler

        slot2.cap = cap_t {
            words: [val1, val2],
        };
        slot1.cteMDBNode = mdb2;
        slot2.cteMDBNode = mdb1;
        {
            let prev_ptr = mdb2.get_prev();
            if prev_ptr != 0 {
                convert_to_mut_type_ref::<cte_t>(prev_ptr).cteMDBNode.set_next(slot1 as *const cte_t as usize);
            }
            let next_ptr = mdb2.get_next();
            if next_ptr != 0 {
                convert_to_mut_type_ref::<cte_t>(next_ptr).cteMDBNode.set_prev(slot1 as *const cte_t as usize);
            }
        }
    }
}


#[inline]
fn cap_removable(cap: &cap_t, slot: *mut cte_t) -> bool {
    match cap.get_cap_type() {
        CapTag::CapNullCap => {
            return true;
        }
        CapTag::CapZombieCap => {
            let n = cap.get_zombie_number();
            let ptr = cap.get_zombie_ptr();
            let z_slot = ptr as *mut cte_t;
            return n == 0 || (n == 1 && slot == z_slot);
        }
        _ => {
            panic!("Invalid cap type , finaliseCap should only return Zombie or NullCap");
        }
    }
}


#[no_mangle]
pub fn insert_new_cap(parent: &mut cte_t, slot: &mut cte_t, cap: &cap_t) {
    let next = parent.cteMDBNode.get_next();
    slot.cap = cap.clone();
    slot.cteMDBNode = mdb_node_t::new(next as usize, 1usize, 1usize,
        parent as *const cte_t as usize);
    if next != 0 {
        let next_ref = convert_to_mut_type_ref::<cte_t>(next);
        next_ref.cteMDBNode.set_prev(slot as *const cte_t as usize);
    }
    parent.cteMDBNode.set_next(slot as *const cte_t as usize);
}


fn setUntypedCapAsFull(srcCap: &cap_t, newCap: &cap_t, srcSlot: &mut cte_t) {
    if srcCap.get_cap_type() == CapTag::CapUntypedCap
        && newCap.get_cap_type() == CapTag::CapUntypedCap
    {
        assert_eq!(srcSlot.cap.get_cap_type(), CapTag::CapUntypedCap);
        if srcCap.get_untyped_ptr() == newCap.get_untyped_ptr()
            && srcCap.get_untyped_block_size() == newCap.get_untyped_block_size()
        {
            srcSlot.cap.set_untyped_free_index(
                MAX_FREE_INDEX(srcCap.get_untyped_block_size())
            );
        }
    }
}