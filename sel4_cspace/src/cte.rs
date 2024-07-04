use super::{
    cap::{cap_t, is_cap_revocable, same_object_as, same_region_as, CapTag},
    deps::{finaliseCap, post_cap_deletion, preemptionPoint},
    mdb::mdb_node_t,
    structures::{finaliseSlot_ret, resolveAddressBits_ret_t},
};
use crate::cap::zombie::capCyclicZombie;
use core::intrinsics::{likely, unlikely};
use core::ptr;
use sel4_common::utils::{convert_to_option_mut_type_ref, MAX_FREE_INDEX};
use sel4_common::{
    sel4_config::wordRadix,
    structures::exception_t,
    utils::{convert_to_mut_type_ref, convert_to_type_ref},
    MASK,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct deriveCap_ret {
    pub status: exception_t,
    pub cap: cap_t,
}

/// 由cap_t和 mdb_node 组成，是CSpace的基本组成单元
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct cte_t {
    pub cap: cap_t,
    pub cteMDBNode: mdb_node_t,
}

impl cte_t {
    pub fn get_ptr(&self) -> usize {
        self as *const cte_t as usize
    }

    pub fn get_offset_slot(&mut self, index: usize) -> &'static mut Self {
        convert_to_mut_type_ref::<Self>(self.get_ptr() + core::mem::size_of::<cte_t>() * index)
    }

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
            let next = convert_to_type_ref::<cte_t>(self.cteMDBNode.get_next());
            if self.is_mdb_parent_of(next) {
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        return exception_t::EXCEPTION_NONE;
    }

    fn is_mdb_parent_of(&self, next: &Self) -> bool {
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
                return badge == next.cap.get_ep_badge()
                    && !(next.cteMDBNode.get_first_badged() != 0);
            }
            CapTag::CapNotificationCap => {
                assert_eq!(next.cap.get_cap_type(), CapTag::CapNotificationCap);
                let badge = self.cap.get_nf_badge();
                if badge == 0 {
                    return true;
                }
                return badge == next.cap.get_nf_badge()
                    && !(next.cteMDBNode.get_first_badged() != 0);
            }
            _ => true,
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

    unsafe fn finalise(&mut self, immediate: bool) -> finaliseSlot_ret {
        let mut ret = finaliseSlot_ret::default();
        while self.cap.get_cap_type() != CapTag::CapNullCap {
            let fc_ret = finaliseCap(&self.cap, self.is_final_cap(), false);
            if cap_removable(&fc_ret.remainder, self) {
                ret.status = exception_t::EXCEPTION_NONE;
                ret.success = true;
                ret.cleanupInfo = fc_ret.cleanupInfo;
                return ret;
            }
            self.cap = fc_ret.remainder;
            if !immediate && capCyclicZombie(&fc_ret.remainder, self) {
                ret.status = exception_t::EXCEPTION_NONE;
                ret.success = false;
                ret.cleanupInfo = fc_ret.cleanupInfo;
                return ret;
            }
            let status = self.reduce_zombie(immediate);
            if exception_t::EXCEPTION_NONE != status {
                ret.status = status;
                ret.success = false;
                ret.cleanupInfo = cap_t::new_null_cap();
                return ret;
            }

            let status = preemptionPoint();
            if exception_t::EXCEPTION_NONE != status {
                ret.status = status;
                ret.success = false;
                ret.cleanupInfo = cap_t::new_null_cap();
                return ret;
            }
        }
        ret
    }

    pub fn delete_all(&mut self, exposed: bool) -> exception_t {
        let fs_ret = unsafe { self.finalise(exposed) };
        if fs_ret.status != exception_t::EXCEPTION_NONE {
            return fs_ret.status;
        }
        if exposed || fs_ret.success {
            self.set_empty(&fs_ret.cleanupInfo);
        }
        return exception_t::EXCEPTION_NONE;
    }

    pub fn delete_one(&mut self) {
        if self.cap.get_cap_type() != CapTag::CapNullCap {
            let fc_ret = unsafe { finaliseCap(&self.cap, self.is_final_cap(), true) };
            assert!(
                cap_removable(&fc_ret.remainder, self)
                    && fc_ret.cleanupInfo.get_cap_type() == CapTag::CapNullCap
            );
            self.set_empty(&cap_t::new_null_cap());
        }
    }

    fn set_empty(&mut self, cleanup_info: &cap_t) {
        if self.cap.get_cap_type() != CapTag::CapNullCap {
            let mdb_node = self.cteMDBNode;
            let prev_addr = mdb_node.get_prev();
            let next_addr = mdb_node.get_next();
            if prev_addr != 0 {
                let prev_node = convert_to_mut_type_ref::<cte_t>(prev_addr);
                prev_node.cteMDBNode.set_next(next_addr);
            }

            if next_addr != 0 {
                let next_node = convert_to_mut_type_ref::<cte_t>(next_addr);
                next_node.cteMDBNode.set_prev(prev_addr);
                let first_badged = ((next_node.cteMDBNode.get_first_badged() != 0)
                    || (mdb_node.get_first_badged() != 0))
                    as usize;
                next_node.cteMDBNode.set_first_badged(first_badged);
            }
            self.cap = cap_t::new_null_cap();
            self.cteMDBNode = mdb_node_t::default();
            unsafe { post_cap_deletion(cleanup_info) };
        }
    }

    fn reduce_zombie(&mut self, immediate: bool) -> exception_t {
        assert_eq!(self.cap.get_cap_type(), CapTag::CapZombieCap);
        let self_ptr = self as *mut cte_t as usize;
        let ptr = self.cap.get_zombie_ptr();
        let n = self.cap.get_zombie_number();
        let zombie_type = self.cap.get_zombie_type();
        assert!(n > 0);
        if immediate {
            let end_slot = unsafe { &mut *((ptr as *mut cte_t).add(n - 1)) };
            let status = end_slot.delete_all(false);
            if status != exception_t::EXCEPTION_NONE {
                return status;
            }
            match self.cap.get_cap_type() {
                CapTag::CapNullCap => {
                    return exception_t::EXCEPTION_NONE;
                }
                CapTag::CapZombieCap => {
                    let ptr2 = self.cap.get_zombie_ptr();
                    if ptr == ptr2
                        && self.cap.get_zombie_number() == n
                        && self.cap.get_zombie_type() == zombie_type
                    {
                        assert_eq!(end_slot.cap.get_cap_type(), CapTag::CapNullCap);
                        self.cap.set_zombie_number(n - 1);
                    } else {
                        assert!(ptr2 == self_ptr && ptr != self_ptr);
                    }
                }
                _ => {
                    panic!("Expected recursion to result in Zombie.")
                }
            }
        } else {
            assert_ne!(ptr, self_ptr);
            let next_slot = convert_to_mut_type_ref::<cte_t>(ptr);
            let cap1 = next_slot.cap;
            let cap2 = self.cap;
            cte_swap(&cap1, next_slot, &cap2, self);
        }
        exception_t::EXCEPTION_NONE
    }

    #[inline]
    fn get_volatile_value(&self) -> usize {
        unsafe {
            let raw_value = ptr::read_volatile((self.get_ptr() + 24) as *const usize);
            let mut value = ((raw_value >> 2) & MASK!(37)) << 2;
            if (value & (1usize << 38)) != 0 {
                value |= 0xffffff8000000000;
            }
            value
        }
    }

    #[inline]
    pub fn revoke(&mut self) -> exception_t {
        while let Some(cte) = convert_to_option_mut_type_ref::<cte_t>(self.get_volatile_value()) {
            if !self.is_mdb_parent_of(cte) {
                break;
            }

            let mut status = cte.delete_all(true);
            if status != exception_t::EXCEPTION_NONE {
                return status;
            }

            status = unsafe { preemptionPoint() };
            if status != exception_t::EXCEPTION_NONE {
                return status;
            }
        }
        return exception_t::EXCEPTION_NONE;
    }
}

/// 将一个cap插入slot中并维护能力派生树
///
/// 将一个new_cap插入到dest slot中并作为src slot的派生子节点插入派生树中
pub fn cte_insert(new_cap: &cap_t, src_slot: &mut cte_t, dest_slot: &mut cte_t) {
    let srcMDB = &mut src_slot.cteMDBNode;
    let srcCap = &(src_slot.cap.clone());
    let mut newMDB = srcMDB.clone();
    let newCapIsRevocable = is_cap_revocable(new_cap, srcCap);
    newMDB.set_prev(src_slot as *const cte_t as usize);
    newMDB.set_revocable(newCapIsRevocable as usize);
    newMDB.set_first_badged(newCapIsRevocable as usize);

    /* Haskell error: "cteInsert to non-empty destination" */
    assert_eq!(dest_slot.cap.get_cap_type(), CapTag::CapNullCap);
    /* Haskell error: "cteInsert: mdb entry must be empty" */
    assert!(dest_slot.cteMDBNode.get_next() == 0 && dest_slot.cteMDBNode.get_prev() == 0);

    setUntypedCapAsFull(srcCap, new_cap, src_slot);

    (*dest_slot).cap = new_cap.clone();
    (*dest_slot).cteMDBNode = newMDB;
    src_slot
        .cteMDBNode
        .set_next(dest_slot as *const cte_t as usize);
    if newMDB.get_next() != 0 {
        let cte_ref = convert_to_mut_type_ref::<cte_t>(newMDB.get_next());
        cte_ref
            .cteMDBNode
            .set_prev(dest_slot as *const cte_t as usize);
    }
}

pub fn insert_new_cap(parent: &mut cte_t, slot: &mut cte_t, cap: &cap_t) {
    let next = parent.cteMDBNode.get_next();
    slot.cap = cap.clone();
    slot.cteMDBNode = mdb_node_t::new(
        next as usize,
        1usize,
        1usize,
        parent as *const cte_t as usize,
    );
    if next != 0 {
        let next_ref = convert_to_mut_type_ref::<cte_t>(next);
        next_ref.cteMDBNode.set_prev(slot as *const cte_t as usize);
    }
    parent.cteMDBNode.set_next(slot as *const cte_t as usize);
}

/// 将一个cap插入slot中并删除原节点
///
/// 将一个new_cap插入到dest slot中并作为替代src slot在派生树中的位置
pub fn cte_move(new_cap: &cap_t, src_slot: &mut cte_t, dest_slot: &mut cte_t) {
    /* Haskell error: "cteInsert to non-empty destination" */
    assert_eq!(dest_slot.cap.get_cap_type(), CapTag::CapNullCap);
    /* Haskell error: "cteInsert: mdb entry must be empty" */
    assert!(dest_slot.cteMDBNode.get_next() == 0 && dest_slot.cteMDBNode.get_prev() == 0);
    let mdb = src_slot.cteMDBNode;
    dest_slot.cap = new_cap.clone();
    src_slot.cap = cap_t::new_null_cap();
    dest_slot.cteMDBNode = mdb;
    src_slot.cteMDBNode = mdb_node_t::new(0, 0, 0, 0);

    let prev_ptr = mdb.get_prev();
    if prev_ptr != 0 {
        let prev_ref = convert_to_mut_type_ref::<cte_t>(prev_ptr);
        prev_ref
            .cteMDBNode
            .set_next(dest_slot as *const cte_t as usize);
    }
    let next_ptr = mdb.get_next();
    if next_ptr != 0 {
        let next_ref = convert_to_mut_type_ref::<cte_t>(next_ptr);
        next_ref
            .cteMDBNode
            .set_prev(dest_slot as *const cte_t as usize);
    }
}

/// 交换两个slot，并将新的cap数据填入
pub fn cte_swap(cap1: &cap_t, slot1: &mut cte_t, cap2: &cap_t, slot2: &mut cte_t) {
    let mdb1 = slot1.cteMDBNode;
    let mdb2 = slot2.cteMDBNode;
    {
        let prev_ptr = mdb1.get_prev();
        if prev_ptr != 0 {
            convert_to_mut_type_ref::<cte_t>(prev_ptr)
                .cteMDBNode
                .set_next(slot2 as *const cte_t as usize);
        }
        let next_ptr = mdb1.get_next();
        if next_ptr != 0 {
            convert_to_mut_type_ref::<cte_t>(next_ptr)
                .cteMDBNode
                .set_prev(slot2 as *const cte_t as usize);
        }
    }

    slot1.cap = cap2.clone();
    //FIXME::result not right due to compiler

    slot2.cap = cap1.clone();
    slot1.cteMDBNode = mdb2;
    slot2.cteMDBNode = mdb1;
    {
        let prev_ptr = mdb2.get_prev();
        if prev_ptr != 0 {
            convert_to_mut_type_ref::<cte_t>(prev_ptr)
                .cteMDBNode
                .set_next(slot1 as *const cte_t as usize);
        }
        let next_ptr = mdb2.get_next();
        if next_ptr != 0 {
            convert_to_mut_type_ref::<cte_t>(next_ptr)
                .cteMDBNode
                .set_prev(slot1 as *const cte_t as usize);
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

fn setUntypedCapAsFull(srcCap: &cap_t, newCap: &cap_t, srcSlot: &mut cte_t) {
    if srcCap.get_cap_type() == CapTag::CapUntypedCap
        && newCap.get_cap_type() == CapTag::CapUntypedCap
    {
        assert_eq!(srcSlot.cap.get_cap_type(), CapTag::CapUntypedCap);
        if srcCap.get_untyped_ptr() == newCap.get_untyped_ptr()
            && srcCap.get_untyped_block_size() == newCap.get_untyped_block_size()
        {
            srcSlot
                .cap
                .set_untyped_free_index(MAX_FREE_INDEX(srcCap.get_untyped_block_size()));
        }
    }
}

/// 从cspace寻址特定的slot
///
/// 从给定的cnode、cap index、和depth中找到对应cap的slot，成功则返回slot指针，失败返回找到的最深的cnode
#[allow(unreachable_code)]
pub fn resolve_address_bits(
    node_cap: &cap_t,
    cap_ptr: usize,
    _n_bits: usize,
) -> resolveAddressBits_ret_t {
    let mut ret = resolveAddressBits_ret_t::default();
    let mut n_bits = _n_bits;
    ret.bitsRemaining = n_bits;
    let mut nodeCap = node_cap.clone();

    if unlikely(nodeCap.get_cap_type() != CapTag::CapCNodeCap) {
        ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
        return ret;
    }

    loop {
        let radixBits = nodeCap.get_cnode_radix();
        let guardBits = nodeCap.get_cnode_guard_size();
        let levelBits = radixBits + guardBits;
        assert_ne!(levelBits, 0);
        let capGuard = nodeCap.get_cnode_guard();
        let guard = (cap_ptr >> ((n_bits - guardBits) & MASK!(wordRadix))) & MASK!(guardBits);
        if unlikely(guardBits > n_bits || guard != capGuard) {
            ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
            return ret;
        }
        if unlikely(levelBits > n_bits) {
            ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
            return ret;
        }
        let offset = (cap_ptr >> (n_bits - levelBits)) & MASK!(radixBits);
        let slot = unsafe { (nodeCap.get_cnode_ptr() as *mut cte_t).add(offset) };

        if likely(n_bits == levelBits) {
            ret.slot = slot;
            ret.bitsRemaining = 0;
            return ret;
        }
        n_bits -= levelBits;
        nodeCap = unsafe { (*slot).cap.clone() };
        if unlikely(nodeCap.get_cap_type() != CapTag::CapCNodeCap) {
            ret.slot = slot;
            ret.bitsRemaining = n_bits;
            return ret;
        }
    }
    panic!("UNREACHABLE");
}
