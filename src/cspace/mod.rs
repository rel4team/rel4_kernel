pub mod cap;
mod cte;
mod mdb;

pub use cte::cte_t;
pub use mdb::mdb_node_t;

use crate::{object::untyped::MAX_FREE_INDEX, cspace::cap::UntypedCap};

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
        let cte_ref = unsafe {
            &mut *(newMDB.get_next() as *mut cte_t)
        };
        cte_ref.cteMDBNode.set_prev(destSlot as *const cte_t as usize);
    }
}

fn setUntypedCapAsFull(srcCap: &cap_t, newCap: &cap_t, srcSlot: &mut cte_t) {
    if srcCap.get_cap_type() == CapTag::CapUntypedCap
        && newCap.get_cap_type() == CapTag::CapUntypedCap
    {
        assert_eq!(srcSlot.cap.get_cap_type(), CapTag::CapUntypedCap);
        if srcCap.get_inner_ref::<UntypedCap>().get_ptr() == newCap.get_inner_ref::<UntypedCap>().get_ptr()
            && srcCap.get_inner_ref::<UntypedCap>().get_block_size() == newCap.get_inner_ref::<UntypedCap>().get_block_size()
        {
            srcSlot.cap.get_inner_mut_ref::<UntypedCap>().set_free_index(
                MAX_FREE_INDEX(srcCap.get_inner_ref::<UntypedCap>().get_block_size())
            );
        }
    }
}