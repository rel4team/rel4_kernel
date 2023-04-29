use crate::{
    config::{seL4_IllegalOperation, seL4_SlotBits, wordBits},
    kernel::{
        boot::current_syscall_error,
        transfermsg::{seL4_CNode_capData_get_guard, seL4_CNode_capData_get_guardSize},
        vspace::pageBitsForSize,
    },
    println,
    structures::{cap_t, cte_t, deriveCap_ret, exception_t, finaliseCap_ret, seL4_CNode_CapData_t},
    MASK,
};

use super::{
    cap::ensureNoChildren,
    structure_gen::{
        cap_asid_pool_cap_get_capASIDPool, cap_cnode_cap_get_capCNodePtr,
        cap_cnode_cap_get_capCNodeRadix, cap_cnode_cap_set_capCNodeGuard,
        cap_cnode_cap_set_capCNodeGuardSize, cap_endpoint_cap_get_capEPBadge,
        cap_endpoint_cap_get_capEPPtr, cap_endpoint_cap_set_capEPBadge,
        cap_frame_cap_get_capFBasePtr, cap_frame_cap_get_capFIsDevice,
        cap_frame_cap_get_capFMappedASID, cap_frame_cap_get_capFSize,
        cap_frame_cap_set_capFMappedASID, cap_frame_cap_set_capFMappedAddress,
        cap_notification_cap_get_capNtfnBadge, cap_notification_cap_set_capNtfnBadge,
        cap_null_cap_new, cap_page_table_cap_get_capPTBasePtr,
        cap_page_table_cap_get_capPTIsMapped, cap_thread_cap_get_capTCBPtr,
        cap_untyped_cap_get_capBlockSize, cap_untyped_cap_get_capPtr, Zombie_new,
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

pub fn Arch_deriveCap(_slot: *mut cte_t, cap: &cap_t) -> deriveCap_ret {
    let mut ret = deriveCap_ret {
        status: exception_t::EXCEPTION_NONE,
        cap: cap_t::default(),
    };
    match cap_get_capType(cap) {
        cap_page_table_cap => {
            if cap_page_table_cap_get_capPTIsMapped(cap) != 0 {
                ret.cap = cap.clone();
                ret.status = exception_t::EXCEPTION_NONE;
            } else {
                println!(" error:this page table cap is not mapped");
                unsafe {
                    current_syscall_error._type = seL4_IllegalOperation;
                    ret.cap = cap_null_cap_new();
                    ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
                }
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
            panic!(" Invalid arch cap type :{}", cap_get_capType(cap));
        }
    }
    ret
}

#[inline]
pub fn isArchCap(_cap: &cap_t) -> bool {
    cap_get_capType(_cap) % 2 != 0
}

#[no_mangle]
pub fn deriveCap(slot: *mut cte_t, cap: &cap_t) -> deriveCap_ret {
    if isArchCap(&cap) {
        return Arch_deriveCap(slot, cap);
    }
    let mut ret = deriveCap_ret {
        status: exception_t::EXCEPTION_NONE,
        cap: cap_t::default(),
    };
    match cap_get_capType(cap) {
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
        cap_irq_control_cap => {
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

pub fn Arch_sameObjectAs(cap_a: &cap_t, cap_b: &cap_t) -> bool {
    if (cap_get_capType(cap_a) == cap_frame_cap) && (cap_get_capType(cap_b) == cap_frame_cap) {
        return (cap_frame_cap_get_capFBasePtr(cap_a) == cap_frame_cap_get_capFBasePtr(cap_b))
            && (cap_frame_cap_get_capFSize(cap_a) == cap_frame_cap_get_capFSize(cap_b))
            && ((cap_frame_cap_get_capFIsDevice(cap_a) == 0)
                == (cap_frame_cap_get_capFIsDevice(cap_b) == 0));
    }
    return sameRegionAs(cap_a, cap_b);
}
pub fn sameObjectAs(cap_a: &cap_t, cap_b: &cap_t) -> bool {
    if cap_get_capType(cap_a) == cap_untyped_cap {
        return false;
    }
    if cap_get_capType(cap_a) == cap_irq_control_cap
        && cap_get_capType(cap_b) == cap_irq_handler_cap
    {
        return false;
    }
    if isArchCap(cap_a) && isArchCap(cap_b) {
        return Arch_sameObjectAs(cap_a, cap_b);
    }
    return sameRegionAs(cap_a, cap_b);
}

pub fn Arch_finaliseCap(cap: &cap_t, _final: bool) -> finaliseCap_ret {
    let mut fc_ret = finaliseCap_ret::default();
    match cap_get_capType(cap) {
        cap_frame_cap => {
            if cap_frame_cap_get_capFMappedASID(cap) != 0 {
                // unmapPage(
                //     cap_frame_cap_get_capFSize(cap),
                //     cap_frame_cap_get_capFMappedASID(cap),
                //     cap_frame_cap_get_capFMappedAddress(cap),
                //     cap_frame_cap_get_capFBasePtr(cap),
                // );
            }
        }
        cap_page_table_cap => {
            // if _final && cap_page_table_cap_get_capPTIsMapped(cap) != 0 {
            //     let asid = cap_page_table_cap_get_capPTMappedASID(cap);
            //     let find_ret = findVSpaceForASID(asid);
            //     let pte = cap_page_table_cap_get_capPTBasePtr(cap);
            //     if find_ret.status == exception_t::EXCEPTION_NONE && find_ret.vspace_root == pte {
            //         deleteASID(asid, pte);
            //     } else {
            //         unmapPageTable(asid, cap_page_table_cap_get_capPTMappedAddress(cap), pte);
            //     }
            // }
        }
        cap_asid_control_cap => {}
        _ => panic!("Invalid cap type :{}", cap_get_capType(cap)),
    }
    fc_ret.remainder = cap_null_cap_new();
    fc_ret.cleanupInfo = cap_null_cap_new();
    fc_ret
}

pub fn finaliseCap(cap: &cap_t, _final: bool, _exposed: bool) -> finaliseCap_ret {
    let mut fc_ret = finaliseCap_ret::default();

    if isArchCap(cap) {
        return Arch_finaliseCap(cap, _final);
    }

    match cap_get_capType(cap) {
        cap_endpoint_cap => {
            if _final {
                // TODO: cancelALLIPC()
                // cancelAllIPC(cap_endpoint_cap_get_capEPPtr(cap) as *const endpoint_t);
            }
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        cap_notification_cap => {
            if _final {}
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        cap_reply_cap | cap_null_cap | cap_domain_cap => {
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        _ => {
            if _exposed {
                panic!("finaliseCap: failed to finalise immediately.");
            }
        }
    }

    match cap_get_capType(cap) {
        cap_cnode_cap => {
            if _final {
                //TODO Zombie_new()
                fc_ret.remainder = Zombie_new(
                    1usize << cap_cnode_cap_get_capCNodeRadix(cap),
                    cap_cnode_cap_get_capCNodeRadix(cap),
                    cap_cnode_cap_get_capCNodePtr(cap),
                );
                fc_ret.cleanupInfo = cap_null_cap_new();
                return fc_ret;
            } else {
                fc_ret.remainder = cap_null_cap_new();
                fc_ret.cleanupInfo = cap_null_cap_new();
                return fc_ret;
            }
        }
        // cap_thread_cap=>{
        //     if _final{

        //     }
        // }
        //FIXME::cap_thread_cap condition not included
        // cap_thread_cap => {
        //     if _final {
        //         let tcb = cap_thread_cap_get_capTCBPtr(cap) as *const tcb_t;
        //         // let cte_ptr =
        //     }
        // }
        _ => {
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
    }
}

pub fn updateCapData(preserve: bool, newData: usize, _cap: &cap_t) -> cap_t {
    let cap = &mut (_cap.clone());
    if isArchCap(cap) {
        return cap.clone();
    }
    match cap_get_capType(cap) {
        cap_endpoint_cap => {
            if !preserve && cap_endpoint_cap_get_capEPBadge(cap) == 0 {
                cap_endpoint_cap_set_capEPBadge(cap, newData);
                return cap.clone();
            } else {
                return cap_null_cap_new();
            }
        }
        cap_notification_cap => {
            if !preserve && cap_notification_cap_get_capNtfnBadge(cap) == 0 {
                cap_notification_cap_set_capNtfnBadge(cap, newData);
                return cap.clone();
            } else {
                return cap_null_cap_new();
            }
        }
        cap_cnode_cap => {
            let w = seL4_CNode_CapData_t { words: [newData] };
            let guardSize = seL4_CNode_capData_get_guardSize(&w);

            if guardSize + cap_cnode_cap_get_capCNodeRadix(cap) > wordBits {
                return cap_null_cap_new();
            } else {
                let guard = seL4_CNode_capData_get_guard(&w) & MASK!(guardSize);
                let mut new_cap = cap.clone();
                cap_cnode_cap_set_capCNodeGuard(&mut new_cap, guard);
                cap_cnode_cap_set_capCNodeGuardSize(&mut new_cap, guardSize);
                return new_cap;
            }
        }
        _ => return cap.clone(),
    }
}
