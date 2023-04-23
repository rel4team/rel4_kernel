
use crate::{
    config::seL4_SlotBits,
    kernel::vspace::pageBitsForSize,
    structures::{cap_t, cte_t, deriveCap_ret, exception_t},
    MASK,
};

use super::{
    cap::ensureNoChildren,
    structure_gen::{
        cap_asid_pool_cap_get_capASIDPool, cap_cnode_cap_get_capCNodePtr,
        cap_cnode_cap_get_capCNodeRadix, cap_endpoint_cap_get_capEPBadge,
        cap_endpoint_cap_get_capEPPtr, cap_frame_cap_get_capFBasePtr, cap_frame_cap_get_capFSize,
        cap_frame_cap_set_capFMappedASID, cap_frame_cap_set_capFMappedAddress, cap_null_cap_new,
        cap_page_table_cap_get_capPTBasePtr, cap_page_table_cap_get_capPTIsMapped,
        cap_thread_cap_get_capTCBPtr, cap_untyped_cap_get_capBlockSize, cap_untyped_cap_get_capPtr,
    },
};

pub const seL4_EndpointBits: usize = 4;
pub const seL4_NotificationBits: usize = 4;
pub const seL4_ReplyBits: usize = 4;
pub const PT_SIZE_BITS: usize = 12;

//cap_tag_t
pub const cap_null_cap: usize = 0;
pub const cap_untyped_cap: usize = 2;
pub const cap_endpoint_cap: usize = 4;
pub const cap_notification_cap: usize = 6;
pub const cap_reply_cap: usize = 8;
pub const cap_cnode_cap: usize = 10;
pub const cap_thread_cap: usize = 12;
pub const cap_irq_control_cap: usize = 14;
pub const cap_irq_handler_cap: usize = 16;
pub const cap_zombie_cap: usize = 18;
pub const cap_domain_cap: usize = 20;
pub const cap_frame_cap: usize = 1;
pub const cap_page_table_cap: usize = 3;
pub const cap_asid_control_cap: usize = 11;
pub const cap_asid_pool_cap: usize = 13;

pub const seL4_UntypedObject: usize = 1;
pub const seL4_TCBObject: usize = 2;
pub const seL4_EndpointObject: usize = 3;
pub const seL4_CapTableObject: usize = 5;
pub const seL4_RISCV_4K_Page: usize = 6;
pub const seL4_RISCV_Mega_Page: usize = 7;
pub const seL4_RISCV_PageTableObject: usize = 8;
const asidInvalid: usize = 0;

#[inline]
pub fn cap_get_capType(cap: &cap_t) -> usize {
    (cap.words[0] >> 59) & 0x1fusize
}

#[inline]
pub fn cap_capType_equals(cap: &cap_t, cap_type_tag: usize) -> i32 {
    (((cap.words[0] >> 59) & 0x1fusize) == cap_type_tag) as i32
}

pub fn cap_get_capPtr(cap: &cap_t) -> usize {
    match cap_get_capType(cap) {
        cap_untyped_cap => return cap_untyped_cap_get_capPtr(cap),
        cap_endpoint_cap => return cap_endpoint_cap_get_capEPPtr(cap),
        cap_notification_cap => return 0,
        cap_cnode_cap => return cap_cnode_cap_get_capCNodePtr(cap),
        cap_page_table_cap => return cap_page_table_cap_get_capPTBasePtr(cap),
        cap_frame_cap => return cap_frame_cap_get_capFBasePtr(cap),
        cap_asid_pool_cap => return cap_asid_pool_cap_get_capASIDPool(cap),
        _ => return 0,
    }
}

pub fn Arch_deriveCap(_slot: *mut cte_t, cap: cap_t) -> deriveCap_ret {
    let mut ret = deriveCap_ret {
        status: exception_t::EXCEPTION_NONE,
        cap: cap_t::default(),
    };
    match cap_get_capType(&cap) {
        cap_page_table_cap => {
            if cap_page_table_cap_get_capPTIsMapped(&cap) != 0 {
                ret.cap = cap.clone();
                ret.status = exception_t::EXCEPTION_NONE;
            } else {
                panic!(" error:this page table cap is not mapped");
            }
        }
        cap_frame_cap => {
            let mut newCap = cap.clone();
            cap_frame_cap_set_capFMappedAddress(&mut newCap, 0);
            cap_frame_cap_set_capFMappedASID(&mut newCap, 0);
            ret.cap = newCap;
        }
        cap_asid_control_cap | cap_asid_pool_cap => {
            ret.cap = cap.clone();
        }
        _ => {
            panic!(" Invalid arch cap type :{}", cap_get_capType(&cap));
        }
    }
    ret
}

#[inline]
pub fn isArchCap(_cap: &cap_t) -> bool {
    cap_get_capType(_cap) % 2 != 0
}

pub fn deriveCap(slot: *mut cte_t, cap: cap_t) -> deriveCap_ret {
    if isArchCap(&cap) {
        return Arch_deriveCap(slot, cap);
    }
    let mut ret = deriveCap_ret {
        status: exception_t::EXCEPTION_NONE,
        cap: cap_t::default(),
    };
    match cap_get_capType(&cap) {
        cap_zombie_cap => {
            ret.cap = cap_null_cap_new();
        }
        cap_untyped_cap => {
            ret.status = ensureNoChildren(slot);
            if ret.status != exception_t::EXCEPTION_NONE {
                ret.cap = cap_null_cap_new();
            } else {
                ret.cap = cap.clone();
            }
        }
        cap_reply_cap => {
            ret.cap = cap_null_cap_new();
        }
        _ => {
            ret.cap = cap.clone();
        }
    }
    ret
}

fn cap_get_capIsPhyaical(cap: &cap_t) -> bool {
    match cap_get_capType(cap) {
        cap_untyped_cap => return true,
        cap_endpoint_cap => return true,
        cap_notification_cap => return true,
        cap_cnode_cap => return true,
        cap_page_table_cap => return true,
        _ => return false,
    }
}

pub fn cap_get_capSizeBits(cap: &cap_t) -> usize {
    match cap_get_capType(cap) {
        cap_untyped_cap => return cap_untyped_cap_get_capBlockSize(cap),
        cap_endpoint_cap => return seL4_EndpointBits,
        cap_notification_cap => return seL4_NotificationBits,
        cap_cnode_cap => return cap_cnode_cap_get_capCNodeRadix(cap) + seL4_SlotBits,
        cap_page_table_cap => return PT_SIZE_BITS,
        cap_null_cap => return 0,
        cap_reply_cap => seL4_ReplyBits,
        _ => return 0,
    }
}

pub fn sameRegionAs(cap1: &cap_t, cap2: &cap_t) -> bool {
    match cap_get_capType(cap1) {
        cap_untyped_cap => {
            if cap_get_capIsPhyaical(cap2) {
                let aBase = cap_untyped_cap_get_capPtr(cap1);
                let bBase = cap_get_capPtr(cap2);

                let aTop = aBase + MASK!(cap_untyped_cap_get_capBlockSize(cap1));
                let bTop = bBase + MASK!(cap_get_capSizeBits(cap2));
                return (aBase <= bBase) && (bTop <= aTop) && (bBase <= bTop);
            }

            return false;
        }
        cap_frame_cap => {
            let botA = cap_frame_cap_get_capFBasePtr(cap1);
            let botB = cap_frame_cap_get_capFBasePtr(cap2);
            let topA =
                botA + ((1usize << (pageBitsForSize(cap_frame_cap_get_capFSize(cap1)))) - 1usize);
            let topB =
                botB + ((1usize << (pageBitsForSize(cap_frame_cap_get_capFSize(cap2)))) - 1usize);
            (botA <= botB) && (topA >= topB) && (botB <= topB)
        }
        cap_endpoint_cap => {
            cap_endpoint_cap_get_capEPPtr(cap1) == cap_endpoint_cap_get_capEPPtr(cap2)
        }
        cap_page_table_cap => {
            cap_page_table_cap_get_capPTBasePtr(cap1) == cap_page_table_cap_get_capPTBasePtr(cap2)
        }
        cap_cnode_cap => {
            (cap_cnode_cap_get_capCNodePtr(cap1) == cap_cnode_cap_get_capCNodePtr(cap2))
                && (cap_cnode_cap_get_capCNodeRadix(cap1) == cap_cnode_cap_get_capCNodeRadix(cap2))
        }
        cap_thread_cap => cap_thread_cap_get_capTCBPtr(cap1) == cap_thread_cap_get_capTCBPtr(cap2),
        _ => {
            return false;
        }
    }
}

pub fn isCapRevocable(_derivedCap: &cap_t, _srcCap: &cap_t) -> bool {
    if isArchCap(_derivedCap) {
        return false;
    }
    match cap_get_capType(_derivedCap) {
        cap_endpoint_cap => {
            return cap_endpoint_cap_get_capEPBadge(_derivedCap)
                != cap_endpoint_cap_get_capEPBadge(_srcCap)
        }
        cap_untyped_cap => return true,
        _ => return false,
    }
}
