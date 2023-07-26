use common::{structures::exception_t, utils::{convert_to_type_ref, convert_to_mut_type_ref}};

use crate::{cap::{cap_t, CapTag, same_region_as, same_object_as, is_cap_revocable}, mdb::mdb_node_t, utils::MAX_FREE_INDEX};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct deriveCap_ret {
    pub status: exception_t,
    pub cap: cap_t,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct cte_t {
    pub cap: cap_t,
    pub cteMDBNode: mdb_node_t,
}

impl cte_t {
    pub fn derive_cap(&mut self, cap: &cap_t) -> deriveCap_ret {
        if cap.isArchCap() {
            return self.arch_derive_cap(cap);
        }
        let mut ret = deriveCap_ret {
            status: exception_t::EXCEPTION_NONE,
            cap: cap_t::default(),
        };

        match cap.get_cap_type() {
            CapTag::CapZombieCap => {
                ret.cap = cap_t::new_null_cap();
            }
            CapTag::CapUntypedCap => {
                ret.status = self.ensure_no_children();
                if ret.status != exception_t::EXCEPTION_NONE {
                    ret.cap = cap_t::new_null_cap();
                } else {
                    ret.cap = cap.clone();
                }
            }
            CapTag::CapReplyCap => {
                ret.cap = cap_t::new_null_cap();
            }
            CapTag::CapIrqControlCap => {
                ret.cap = cap_t::new_null_cap();
            }
            _ => {
                ret.cap = cap.clone();
            }
        }
        ret
    }

    fn arch_derive_cap(&mut self, cap: &cap_t) -> deriveCap_ret {
        let mut ret = deriveCap_ret {
            status: exception_t::EXCEPTION_NONE,
            cap: cap_t::default(),
        };
        match cap.get_cap_type() {
            CapTag::CapPageTableCap => {
                if cap.get_pt_is_mapped() != 0 {
                    ret.cap = cap.clone();
                    ret.status = exception_t::EXCEPTION_NONE;
                } else {
                    ret.cap = cap_t::new_null_cap();
                    ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            CapTag::CapFrameCap => {
                let mut newCap = cap.clone();
                newCap.set_frame_mapped_address(0);
                newCap.set_frame_mapped_asid(0);
                ret.cap = newCap;
            }
            CapTag::CapASIDControlCap | CapTag::CapASIDPoolCap => {
                ret.cap = cap.clone();
            }
            _ => {
                panic!(" Invalid arch cap type : {}", cap.get_cap_type() as usize);
            }
        }
        ret
    }

    pub fn ensure_no_children(&self) -> exception_t {
        if self.cteMDBNode.get_next() != 0 {
            unsafe {
                let next = & *(self.cteMDBNode.get_next() as *mut cte_t);
                if self.is_mdb_parent_of(next) {
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
        }
        return exception_t::EXCEPTION_NONE;
    }

    pub fn is_mdb_parent_of(&self, next: &Self) -> bool {
        if !(self.cteMDBNode.get_revocable() != 0) {
            return false;
        }
        if !same_region_as(&self.cap, &next.cap) {
            return false;
        }

        match self.cap.get_cap_type() {
            CapTag::CapEndpointCap => {
                assert_eq!(next.cap.get_cap_type(), CapTag::CapEndpointCap);
                let badge = self.cap.get_ep_badge();
                if badge == 0 {
                    return true;
                }
                return badge == next.cap.get_ep_badge() &&
                    !(next.cteMDBNode.get_first_badged() != 0);
            }
            CapTag::CapNotificationCap => {
                assert_eq!(next.cap.get_cap_type(), CapTag::CapNotificationCap);
                let badge = self.cap.get_nf_badge();
                if badge == 0 {
                    return true;
                }
                return badge == next.cap.get_nf_badge() &&
                    !(next.cteMDBNode.get_first_badged() != 0);
            }
            _ => true
        }
    }

    pub fn is_final_cap(&self) -> bool {
        let mdb = &self.cteMDBNode;
        let prev_is_same_obj = if mdb.get_prev() == 0 {
            false
        } else {
            let prev = convert_to_type_ref::<cte_t>(mdb.get_prev());
            same_object_as(&prev.cap, &self.cap)
        };

        if prev_is_same_obj {
            false
        } else {
            if mdb.get_next() == 0 {
                true
            } else {
                let next = convert_to_type_ref::<cte_t>(mdb.get_next());
                return !same_object_as(&self.cap, &next.cap);
            }
        }
    }

    pub fn is_long_running_delete(&self) -> bool {
        if self.cap.get_cap_type() == CapTag::CapNullCap || !self.is_final_cap() {
            return false;
        }
        match self.cap.get_cap_type() {
            CapTag::CapThreadCap | CapTag::CapZombieCap | CapTag::CapCNodeCap => true,
            _ => false,
        }
    }
    
}


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
    /* Haskell error: "cteInsert to non-empty destination" */
    assert_eq!(destSlot.cap.get_cap_type(), CapTag::CapNullCap);
    /* Haskell error: "cteInsert: mdb entry must be empty" */
    assert!(
        destSlot.cteMDBNode.get_next() == 0
            && destSlot.cteMDBNode.get_prev() == 0
    );
    let mdb = srcSlot.cteMDBNode;
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


#[no_mangle]
pub fn cte_swap(cap1: &cap_t, slot1: &mut cte_t, cap2: &cap_t, slot2: &mut cte_t) {
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


#[inline]
pub fn cap_removable(cap: &cap_t, slot: *mut cte_t) -> bool {
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