use crate::structures::{cap_t, cap_tag_t, endpoint_t, mdb_node_t, notification_t, thread_state_t};

//CSpace relevant
use core::default::Default;
use core::intrinsics::{likely, unlikely};

use crate::MASK;

use super::objecttype::*;

//zombie config
pub const wordRadix: usize = 6;
pub const ZombieType_ZombieTCB: usize = 1usize << wordRadix;
pub const TCB_CNODE_RADIX: usize = 4;

pub fn ZombieType_ZombieCNode(n: usize) -> usize {
    return n & MASK!(wordRadix);
}

//mdb relevant
#[inline]
pub fn mdb_node_new(
    mdbNext: usize,
    mdbRevocable: usize,
    mdbFirstBadged: usize,
    mdbPrev: usize,
) -> mdb_node_t {
    let mut mdb_node = mdb_node_t::default();

    mdb_node.words[0] = 0 | mdbPrev << 0;

    mdb_node.words[1] = 0
        | (mdbNext & 0x7ffffffffcusize) >> 0
        | (mdbRevocable & 0x1usize) << 1
        | (mdbFirstBadged & 0x1usize) << 0;
    mdb_node
}

#[inline]
pub fn mdb_node_get_mdbNext(mdb_node: &mdb_node_t) -> usize {
    let mut ret: usize;
    ret = (mdb_node.words[1] & 0x7ffffffffcusize) << 0;
    /* Possibly sign extend */
    if core::intrinsics::likely(!!(true && (ret & (1usize << 38) != 0))) {
        ret |= 0xffffff8000000000;
    }
    ret| 0xffffff8000000000
}

#[inline]
pub fn mdb_node_ptr_set_mdbNext(mdb_node: &mut mdb_node_t, v64: usize) {
    assert!(
        (((!0x7ffffffffcusize << 0) | 0xffffff8000000000) & v64)
            == if true && (v64 & (1usize << (38))) != 0 {
                0xffffff8000000000
            } else {
                0
            }
    );
    (mdb_node).words[1] = !0x7ffffffffcusize;
    (mdb_node).words[1] |= (v64 >> 0) & 0x7ffffffffc;
}

#[inline]
pub fn mdb_node_get_mdbRevocable(mdb_node: &mdb_node_t) -> usize {
    let mut ret: usize;
    ret = (mdb_node.words[1] & 0x2usize) >> 1;
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    ret
}

#[inline]
pub fn mdb_node_get_mdbFirstBadged(mdb_node: &mdb_node_t) -> usize {
    let mut ret: usize;
    ret = (mdb_node.words[1] & 0x1usize) >> 0;
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    ret
}

#[inline]
pub fn mdb_node_set_mdbRevocable(mut mdb_node: mdb_node_t, v64: usize) -> mdb_node_t {
    assert!(
        (((!0x2usize >> 1) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );
    mdb_node.words[1] &= !0x2usize;
    mdb_node.words[1] |= (v64 << 1) & 0x2;
    mdb_node
}

#[inline]
pub fn mdb_node_set_mdbFirstBadged(mut mdb_node: mdb_node_t, v64: usize) -> mdb_node_t {
    assert!(
        (((!0x1usize >> 0) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );
    mdb_node.words[1] &= !0x1usize;
    mdb_node.words[1] |= (v64 << 0) & 0x1usize;
    mdb_node
}

#[inline]
pub fn mdb_node_get_mdbPrev(mdb_node: &mdb_node_t) -> usize {
    let mut ret: usize;
    ret = (mdb_node.words[0] & 0xffffffffffffffffusize) >> 0;
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    ret
}

#[inline]
pub fn mdb_node_set_mdbPrev(mdb_node: &mut mdb_node_t, v64: usize) {
    assert!(
        (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );
    mdb_node.words[0] &= !0xffffffffffffffffusize;
    mdb_node.words[0] |= (v64 << 0) & 0xffffffffffffffffusize;
}

#[inline]
pub fn mdb_node_ptr_set_mdbPrev(mdb_node: &mut mdb_node_t, v64: usize) {
    assert!(
        (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );
    (mdb_node).words[0] &= !0xffffffffffffffffusize;
    (mdb_node).words[0] |= (v64 << 0) & 0xffffffffffffffffusize;
}

//cap relevant

#[inline]
pub fn cap_get_max_free_index(cap: &cap_t) -> usize {
    let ans = cap_untyped_cap_get_capBlockSize(cap);
    let sel4_MinUntypedbits: usize = 4;
    (1usize << ans) - sel4_MinUntypedbits
}

#[inline]
pub fn cap_get_capType(cap: &cap_t) -> usize {
    (cap.words[0] >> 59) & 0x1fusize
}

#[inline]
pub fn cap_capType_equals(cap: &cap_t, cap_type_tag: usize) -> i32 {
    (((cap.words[0] >> 59) & 0x1fusize) == cap_type_tag) as i32
}

#[inline]
pub fn cap_null_cap_new() -> cap_t {
    let mut cap = cap_t::default();
    assert!(
        (cap_tag_t::cap_null_cap as usize & !0x1fusize)
            == (if true && (cap_tag_t::cap_null_cap as usize & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[0] = 0 | (cap_tag_t::cap_null_cap as usize & 0x1fusize) << 59;
    cap.words[1] = 0;

    cap
}

#[inline]
pub fn cap_untyped_cap_new(
    capFreeIndex: usize,
    capIsDevice: usize,
    capBlockSize: usize,
    capPtr: usize,
) -> cap_t {
    let mut cap = cap_t::default();
    assert!(
        (capFreeIndex & !0x7fffffffffusize)
            == (if true && (capFreeIndex & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capIsDevice & !0x1usize)
            == (if true && (capIsDevice & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capBlockSize & !0x3fusize)
            == (if true && (capBlockSize & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (cap_tag_t::cap_untyped_cap as usize & !0x1fusize)
            == (if true && (cap_tag_t::cap_untyped_cap as usize & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capPtr & !0x7fffffffffusize)
            == (if true && (capPtr & (1usize << 38)) != 0 {
                0xffffff8000000000
            } else {
                0
            })
    );

    cap.words[0] = 0
        | (cap_tag_t::cap_untyped_cap as usize & 0x1fusize) << 59
        | (capPtr & 0x7fffffffffusize) >> 0;
    cap.words[1] = 0
        | (capFreeIndex & 0x7fffffffffusize) << 25
        | (capIsDevice & 0x1usize) << 6
        | (capBlockSize & 0x3fusize) << 0;
    cap
}

#[inline]
pub fn cap_untyped_cap_get_capIsDevice(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_untyped_cap as usize);
    ret = (cap.words[1] & 0x40usize) >> 6;
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    ret
}

#[inline]
pub fn cap_untyped_cap_get_capBlockSize(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_untyped_cap as usize);
    ret = (cap.words[1] & 0x3fusize) >> 0;
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    ret
}
#[inline]
pub fn cap_untyped_cap_get_capFreeIndex(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_untyped_cap as usize);

    ret = (cap.words[1] & 0xfffffffffe000000usize) >> 25;
    if unlikely(!!(false && (ret & (1usize << (38)) != 0))) {
        ret |= 0x0;
    }
    ret
}

#[inline]
pub fn cap_untyped_cap_set_capFreeIndex(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_untyped_cap as usize);
    assert!(
        (((!0xfffffffffe000000usize >> 25) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[1] &= !0xfffffffffe000000usize;
    cap.words[1] |= (v64 << 25) & 0xfffffffffe000000usize;
}

#[inline]
pub fn cap_untyped_cap_ptr_set_capFreeIndex(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_untyped_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0xfffffffffe000000usize >> 25) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[1] &= !0xfffffffffe000000usize;
    cap.words[1] |= (v64 << 25) & 0xfffffffffe000000usize;
}

#[inline]
pub fn cap_untyped_cap_get_capPtr(cap: &cap_t) -> usize {
    let mut ret;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_untyped_cap as usize);

    ret = (cap.words[0] & 0x7fffffffffusize) << 0;
    /* Possibly sign extend */
    if likely(!!(true && (ret & (1usize << (38))) != 0)) {
        ret |= 0xffffff8000000000;
    }
    ret| 0xffffff8000000000
}

#[inline]
pub fn cap_endpoint_cap_new(
    capEPBadge: usize,
    capCanGrantReply: usize,
    capCanGrant: usize,
    capCanSend: usize,
    capCanReceive: usize,
    capEPPtr: usize,
) -> cap_t {
    let mut cap = cap_t::default();

    /* fail if user has passed bits that we will override */
    assert!(
        (capCanGrantReply & !0x1usize)
            == (if true && (capCanGrantReply & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capCanGrant & !0x1usize)
            == (if true && (capCanGrant & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capCanSend & !0x1usize)
            == (if true && (capCanSend & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capCanReceive & !0x1usize)
            == (if true && (capCanReceive & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capEPPtr & !0x7fffffffffusize)
            == (if true && (capEPPtr & (1usize << 38)) != 0 {
                0xffffff8000000000
            } else {
                0
            })
    );
    assert!(
        (cap_tag_t::cap_endpoint_cap as usize & !0x1fusize)
            == (if true && (cap_tag_t::cap_endpoint_cap as usize & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[0] = 0
        | (capCanGrantReply & 0x1usize) << 58
        | (capCanGrant & 0x1usize) << 57
        | (capCanSend & 0x1usize) << 55
        | (capCanReceive & 0x1usize) << 56
        | (capEPPtr & 0x7fffffffffusize) >> 0
        | (cap_tag_t::cap_endpoint_cap as usize & 0x1fusize) << 59;
    cap.words[1] = 0 | capEPBadge << 0;
    cap
}

#[inline]
pub fn cap_endpoint_cap_get_capEPBadge(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);

    ret = (cap.words[1] & 0xffffffffffffffffusize) >> 0;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    return ret;
}

#[inline]
pub fn cap_endpoint_cap_set_capEPBadge(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[1] &= !0xffffffffffffffffusize;
    cap.words[1] |= (v64 << 0) & 0xffffffffffffffffusize;
}

#[inline]
pub fn cap_endpoint_cap_get_capCanGrantReply(_cap: *const cap_t) -> usize {
    unsafe {
        let cap = *_cap;
        let mut ret: usize;
        assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);

        ret = (cap.words[0] & 0x400000000000000usize) >> 58;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        return ret;
    }
}

#[inline]
pub fn cap_endpoint_cap_set_capCanGrantReply(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0x400000000000000usize >> 58) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );
    cap.words[0] &= !0x400000000000000usize;
    cap.words[0] |= (v64 << 58) & 0x400000000000000usize;
}

#[inline]
pub fn cap_endpoint_cap_get_capCanGrant(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);

    ret = (cap.words[0] & 0x200000000000000usize) >> 57;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    return ret;
}
#[inline]
pub fn cap_endpoint_cap_set_capCanGrant(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0x200000000000000usize >> 57) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[0] &= !0x200000000000000usize;
    cap.words[0] |= (v64 << 57) & 0x200000000000000usize;
}

#[inline]
pub fn cap_endpoint_cap_get_capCanReceive(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);

    ret = (cap.words[0] & 0x100000000000000usize) >> 56;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    return ret;
}

#[inline]
pub fn cap_endpoint_cap_set_capCanReceive(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0x100000000000000usize >> 56) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[0] &= !0x100000000000000usize;
    cap.words[0] |= (v64 << 56) & 0x100000000000000usize;
}

#[inline]
pub fn cap_endpoint_cap_get_capCanSend(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);

    ret = (cap.words[0] & 0x80000000000000usize) >> 55;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    return ret;
}

#[inline]
pub fn cap_endpoint_cap_set_capCanSend(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0x80000000000000usize >> 55) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[0] &= !0x80000000000000usize;
    cap.words[0] |= (v64 << 55) & 0x80000000000000usize;
}

#[inline]
pub fn cap_endpoint_cap_get_capEPPtr(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_endpoint_cap as usize);

    ret = (cap.words[0] & 0x7fffffffffusize) << 0;
    /* Possibly sign extend */
    if likely(!!(true && (ret & (1usize << (38))) != 0)) {
        ret |= 0xffffff8000000000;
    }
    ret| 0xffffff8000000000
}

//FIXME::notification relevant cap not implemented

//FIXME::reply relevant cap not implemented

#[inline]
pub fn cap_cnode_cap_get_capCNodeGuard(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_cnode_cap as usize);

    ret = (cap.words[1] & 0xffffffffffffffffusize) >> 0;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    return ret;
}

#[inline]
pub fn cap_cnode_cap_set_capCNodeGuard(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_cnode_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[1] &= !0xffffffffffffffffusize;
    cap.words[1] |= (v64 << 0) & 0xffffffffffffffffusize;
}

#[inline]
pub fn cap_cnode_cap_get_capCNodeGuardSize(cap: &mut cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_cnode_cap as usize);

    ret = (cap.words[0] & 0x7e0000000000000usize) >> 53;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    return ret;
}

#[inline]
pub fn cap_cnode_cap_set_capCNodeGuardSize(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_cnode_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0x7e0000000000000usize >> 53) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[0] &= !0x7e0000000000000usize;
    cap.words[0] |= (v64 << 53) & 0x7e0000000000000usize;
}

#[inline]
pub fn cap_cnode_cap_get_capCNodeRadix(cap: &cap_t) -> usize {
    let mut ret;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_cnode_cap as usize);

    ret = (cap.words[0] & 0x1f800000000000usize) >> 47;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    return ret;
}

#[inline]
pub fn cap_cnode_cap_get_capCNodePtr(cap: &cap_t) -> usize {
    let mut ret: usize;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_cnode_cap as usize);

    ret = (cap.words[0] & 0x3fffffffffusize) << 1;
    /* Possibly sign extend */
    if likely(!!(true && (ret & (1usize << (38))) != 0)) {
        ret |= 0xffffff8000000000;
    }
    ret| 0xffffff8000000000
}

#[inline]
pub fn isArchCap(cap: &cap_t) -> bool {
    cap_get_capType(cap) % 2 != 0
}

//zombie cap relevant
#[inline]
pub fn cap_zombie_cap_new(capZombieID: usize, capZombieType: usize) -> cap_t {
    let mut cap = cap_t::default();
    /* fail if user has passed bits that we will override */
    assert!(
        (cap_tag_t::cap_zombie_cap as usize & !0x1fusize)
            == (if true && (cap_tag_t::cap_zombie_cap as usize & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capZombieType & !0x7fusize)
            == (if true && (capZombieType & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[0] = 0
        | (cap_tag_t::cap_zombie_cap as usize & 0x1fusize) << 59
        | (capZombieType & 0x7fusize) << 0;
    cap.words[1] = 0 | capZombieID << 0;
    cap
}

#[inline]
pub fn cap_zombie_cap_get_capZombieID(cap: &cap_t) -> usize {
    let mut ret;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_zombie_cap as usize);

    ret = (cap.words[1] & 0xffffffffffffffffusize) >> 0;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    ret
}

#[inline]
pub fn cap_zombie_cap_set_capZombieID(cap: &mut cap_t, v64: usize) {
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_zombie_cap as usize);
    /* fail if user has passed bits that we will override */
    assert!(
        (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
            == (if false && (v64 & (1usize << (38))) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[1] &= !0xffffffffffffffffusize;
    cap.words[1] |= (v64 << 0) & 0xffffffffffffffffusize;
}

#[inline]
pub fn cap_zombie_cap_get_capZombieType(cap: &cap_t) -> usize {
    let mut ret;
    assert!(((cap.words[0] >> 59) & 0x1f) == cap_tag_t::cap_zombie_cap as usize);

    ret = (cap.words[0] & 0x7fusize) >> 0;
    /* Possibly sign extend */
    if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
        ret |= 0x0;
    }
    return ret;
}

#[inline]
pub fn Zombie_new(number: usize, _type: usize, ptr: usize) -> cap_t {
    let mask: usize;
    if _type == ZombieType_ZombieTCB {
        mask = MASK!(TCB_CNODE_RADIX + 1);
    } else {
        mask = MASK!(_type + 1);
    }
    return cap_zombie_cap_new((ptr & !mask) | (number & mask), _type);
}

#[inline]
pub fn cap_zombie_cap_get_capZombieBits(_cap: &cap_t) -> usize {
    let _type = cap_zombie_cap_get_capZombieType(_cap);
    if _type == ZombieType_ZombieTCB {
        return TCB_CNODE_RADIX;
    }
    return ZombieType_ZombieCNode(_type);
}

#[inline]
pub fn cap_zombie_cap_get_capZombieNumber(_cap: &cap_t) -> usize {
    let radix = cap_zombie_cap_get_capZombieBits(_cap);
    return cap_zombie_cap_get_capZombieID(_cap) & MASK!(radix + 1);
}
#[inline]
pub fn cap_zombie_cap_get_capZombiePtr(cap: &cap_t) -> usize {
    let radix = cap_zombie_cap_get_capZombieBits(cap);
    return cap_zombie_cap_get_capZombieID(cap) & !MASK!(radix + 1);
}
#[inline]
pub fn cap_zombie_cap_set_capZombieNumber(cap: &mut cap_t, n: usize) {
    let radix = cap_zombie_cap_get_capZombieBits(cap);
    let ptr = cap_zombie_cap_get_capZombieID(cap) & !MASK!(radix + 1);
    cap_zombie_cap_set_capZombieID(cap, ptr | (n & MASK!(radix + 1)));
}

#[inline]
pub fn cap_page_table_cap_new(
    capPTMappedASID: usize,
    capPTBasePtr: usize,
    capPTIsMapped: usize,
    capPTMappedAddress: usize,
) -> cap_t {
    let mut cap = cap_t::default();

    cap.words[0] = 0
        | (cap_page_table_cap as usize & 0x1fusize) << 59
        | (capPTIsMapped & 0x1usize) << 39
        | (capPTMappedAddress & 0x7fffffffffusize) >> 0;
    cap.words[1] =
        0 | (capPTMappedASID & 0xffffusize) << 48 | (capPTBasePtr & 0x7f_ffff_ffffusize) << 9;
    cap
}

#[inline]
pub fn cap_page_table_cap_get_capPTMappedASID(cap: &cap_t) -> usize {
    let ret = (cap.words[1] & 0xffff000000000000usize) >> 48;
    ret
}

#[inline]
pub fn cap_page_table_cap_set_capPTMappedASID(cap: &mut cap_t, v64: usize) {
    cap.words[1] &= !0xffff000000000000usize;
    cap.words[1] |= (v64 << 48) & 0xffff000000000000usize;
}

#[inline]
pub fn cap_page_table_cap_get_capPTBasePtr(cap: &cap_t) -> usize {
    let ret = (cap.words[1] & 0xfffffffffe00usize) >> 9;
    ret| 0xffffff8000000000
}

#[inline]
pub fn cap_page_table_cap_get_capPTIsMapped(cap: &cap_t) -> usize {
    let ret = (cap.words[0] & 0x8000000000usize) >> 39;
    ret
}

#[inline]
pub fn cap_page_table_cap_set_capPTIsMapped(cap: &mut cap_t, v64: usize) {
    cap.words[0] &= !0x8000000000usize;
    cap.words[0] |= (v64 << 39) & 0x8000000000usize;
}

#[inline]
pub fn cap_page_table_cap_ptr_set_capPTIsMapped(cap: &mut cap_t, v64: usize) {
    cap.words[0] &= !0x8000000000usize;
    cap.words[0] |= (v64 << 39) & 0x8000000000usize;
}
#[inline]
pub fn cap_page_table_cap_get_capPTMappedAddress(cap: &cap_t) -> usize {
    let ret = (cap.words[0] & 0x7fffffffffusize) << 0;
    ret| 0xffffff8000000000
}

#[inline]
pub fn cap_page_table_cap_set_capPTMappedAddress(cap: &mut cap_t, v64: usize) {
    cap.words[0] &= !0x7fffffffffusize;
    cap.words[0] |= (v64 >> 0) & 0x7fffffffffusize;
}

#[inline]
pub fn cap_frame_cap_new(
    capFMappedASID: usize,
    capFBasePtr: usize,
    capFSize: usize,
    capFVMRights: usize,
    capFIsDevice: usize,
    capFMappedAddress: usize,
) -> cap_t {
    let mut cap = cap_t::default();
    cap.words[0] = 0
        | (cap_frame_cap & 0x1fusize) << 59
        | (capFSize & 0x3usize) << 57
        | (capFVMRights & 0x3usize) << 55
        | (capFIsDevice & 0x1usize) << 54
        | (capFMappedAddress & 0x7fffffffffusize) >> 0;
    cap.words[1] =
        0 | (capFMappedASID & 0xffffusize) << 48 | (capFBasePtr & 0x7fffffffffusize) << 9;
    cap
}

#[inline]
pub fn cap_frame_cap_get_capFMappedASID(cap: &cap_t) -> usize {
    let ret = (cap.words[1] & 0xffff000000000000usize) >> 48;
    ret
}

#[inline]
pub fn cap_frame_cap_set_capFMappedASID(cap: &mut cap_t, v64: usize) {
    cap.words[1] &= !0xffff000000000000usize;
    cap.words[1] |= (v64 << 48) & 0xffff000000000000usize;
}

#[inline]
pub fn cap_frame_cap_get_capFBasePtr(cap: &cap_t) -> usize {
    let ret = (cap.words[1] & 0xfffffffffe00usize) >> 9;
    ret| 0xffffff8000000000
}

#[inline]
pub fn cap_frame_cap_get_capFSize(cap: &cap_t) -> usize {
    let ret = (cap.words[0] & 0x600000000000000usize) >> 57;
    ret
}

#[inline]
pub fn cap_frame_cap_get_capFVMRights(cap: &cap_t) -> usize {
    let ret = (cap.words[0] & 0x180000000000000usize) >> 55;
    ret
}

#[inline]
pub fn cap_frame_cap_set_capFVMRights(cap: &mut cap_t, v64: usize) {
    cap.words[0] &= !0x180000000000000usize;
    cap.words[0] |= (v64 << 55) & 0x180000000000000usize;
}

#[inline]
pub fn cap_frame_cap_get_capFIsDevice(cap: &cap_t) -> usize {
    let ret = (cap.words[0] & 0x40000000000000usize) >> 54;
    ret
}

#[inline]
pub fn cap_frame_cap_get_capFMappedAddress(cap: &cap_t) -> usize {
    let ret = (cap.words[0] & 0x7fffffffffusize) << 0;
    ret| 0xffffff8000000000
}
#[inline]
pub fn cap_frame_cap_set_capFMappedAddress(cap: &mut cap_t, v64: usize) {
    cap.words[0] &= !0x7fffffffffusize;
    cap.words[0] |= (v64 >> 0) & 0x7fffffffffusize;
}

#[inline]
pub fn pte_ptr_get_ppn(pte_ptr: *const usize) -> usize {
    unsafe {
        let ret = ((*pte_ptr) & 0x3f_ffff_ffff_fc00usize) >> 10;
        ret
    }
}
#[inline]
pub fn pte_ptr_get_execute(pte_ptr: *const usize) -> usize {
    unsafe {
        let ret = ((*pte_ptr) & 0x8usize) >> 3;
        ret
    }
}

#[inline]
pub fn pte_ptr_get_write(pte_ptr: *const usize) -> usize {
    unsafe {
        let ret = ((*pte_ptr) & 0x4usize) >> 2;
        ret
    }
}

#[inline]
pub fn pte_ptr_get_read(pte_ptr: *const usize) -> usize {
    unsafe {
        let ret = ((*pte_ptr) & 0x2usize) >> 1;
        ret
    }
}

#[inline]
pub fn pte_ptr_get_valid(pte_ptr: *const usize) -> usize {
    unsafe {
        let ret = ((*pte_ptr) & 0x1usize) >> 0;
        ret
    }
}

#[inline]
pub fn cap_asid_control_cap_new() -> cap_t {
    let mut cap = cap_t::default();
    cap.words[0] = 0 | (cap_asid_control_cap & 0x1fusize) << 59;
    cap.words[1] = 0;
    cap
}

#[inline]
pub fn cap_asid_cap_new(capASIDBase: usize, capASIDPool: usize) -> cap_t {
    let mut cap = cap_t::default();
    cap.words[0] = 0
        | (cap_asid_pool_cap & 0x1fusize) << 59
        | (capASIDBase & 0xffffusize) << 43
        | (capASIDPool & 0x7ffffffffcusize) >> 2;
    cap.words[1] = 0;
    cap
}

#[inline]
pub fn cap_asid_pool_cap_get_capASIDBase(cap: &cap_t) -> usize {
    let ret = ((*cap).words[0] & 0x7fff80000000000usize) >> 43;
    ret
}

#[inline]
pub fn cap_asid_pool_cap_get_capASIDPool(cap: &cap_t) -> usize {
    let ret = (cap.words[0] & 0x1fffffffffusize) << 2;
    ret| 0xffffff8000000000
}

#[inline]
pub fn thread_state_new() -> thread_state_t {
    let state = thread_state_t { words: [0; 3] };
    state
}

#[inline]
pub fn thread_state_get_blockingIPCBadge(thread_state_ptr: &thread_state_t) -> usize {
    let ret = (thread_state_ptr).words[2] & 0xffffffffffffffffusize;
    ret| 0xffffff8000000000
}

#[inline]
pub fn thread_state_set_blockingIPCBadge(
    mut thread_state_ptr: thread_state_t,
    v64: usize,
) -> thread_state_t {
    (thread_state_ptr).words[2] &= !0xffffffffffffffffusize;
    (thread_state_ptr).words[2] |= v64 & 0xffffffffffffffffusize;
    thread_state_ptr
}

#[inline]
pub fn thread_state_get_blockingIPCCanGrant(thread_state_ptr: &thread_state_t) -> usize {
    let ret = ((thread_state_ptr).words[1] & 0x8usize) >> 3;
    ret
}

#[inline]
pub fn thread_state_set_blockingIPCCanGrant(thread_state_ptr: &mut thread_state_t, v64: usize) {
    (thread_state_ptr).words[1] &= !0x8usize;
    (thread_state_ptr).words[1] |= (v64 << 3) & 0x8usize;
}

#[inline]
pub fn thread_state_get_blockingIPCCanGrantReply(thread_state_ptr: &thread_state_t) -> usize {
    let ret = ((thread_state_ptr).words[1] & 0x4usize) >> 2;
    ret
}

#[inline]
pub fn thread_state_set_blockingIPCCanGrantReply(
    thread_state_ptr: &mut thread_state_t,
    v64: usize,
) {
    (thread_state_ptr).words[1] &= !0x4usize;
    (thread_state_ptr).words[1] |= (v64 << 2) & 0x4usize;
}

#[inline]
pub fn thread_state_get_blockingIPCIsCall(thread_state_ptr: &thread_state_t) -> usize {
    let ret = ((thread_state_ptr).words[1] & 0x2usize) >> 1;
    ret
}

#[inline]
pub fn thread_state_set_blockingIPCIsCall(thread_state_ptr: &mut thread_state_t, v64: usize) {
    (thread_state_ptr).words[1] &= !0x2usize;
    (thread_state_ptr).words[1] |= (v64 << 1) & 0x2usize;
}

#[inline]
pub fn thread_state_get_tcbQueued(thread_state_ptr: &thread_state_t) -> usize {
    let ret = ((thread_state_ptr).words[1] & 0x1usize) >> 0;
    ret
}

#[inline]
pub fn thread_state_set_tcbQueued(thread_state_ptr: &mut thread_state_t, v64: usize) {
    thread_state_ptr.words[1] &= !0x1usize;
    thread_state_ptr.words[1] |= (v64 << 0) & 0x1usize;
}

#[inline]
pub fn thread_state_get_blockingObject(thread_state_ptr: &thread_state_t) -> usize {
    let ret = ((thread_state_ptr).words[0] & 0x7ffffffff0usize) << 0;
    ret
}

#[inline]
pub fn thread_state_set_blockingObject(thread_state_ptr: &mut thread_state_t, v64: usize) {
    (thread_state_ptr).words[0] &= !0x7ffffffff0usize;
    (thread_state_ptr).words[0] |= (v64 >> 0) & 0x7ffffffff0usize;
}

#[inline]
pub fn thread_state_get_tsType(thread_state_ptr: &thread_state_t) -> usize {
    let ret = (thread_state_ptr).words[0] & 0xfusize;
    ret
}

#[inline]
pub fn thread_state_set_tsType(thread_state_ptr: &mut thread_state_t, v64: usize) {
    (thread_state_ptr).words[0] &= !0xfusize;
    (thread_state_ptr).words[0] |= v64 & 0xfusize;
}

#[inline]
pub fn cap_domain_cap_new() -> cap_t {
    let mut cap = cap_t::default();
    cap.words[0] = 0 | (cap_domain_cap & 0x1fusize) << 59;
    cap.words[1] = 0;
    cap
}

#[inline]
pub fn endpoint_ptr_set_epQueue_head(ptr: &mut endpoint_t, v64: usize) {
    (ptr).words[1] &= !0xffffffffffffffffusize;
    (ptr).words[1] |= (v64 << 0) & 0xffffffffffffffff;
}

#[inline]
pub fn endpoint_ptr_get_epQueue_head(ptr: &endpoint_t) -> usize {
    let ret = ((ptr).words[1] & 0xffffffffffffffffusize) >> 0;
    ret| 0xffffff8000000000
}

#[inline]
pub fn endpoint_ptr_set_epQueue_tail(ptr: &mut endpoint_t, v64: usize) {
    (ptr).words[0] &= !0x7ffffffffcusize;
    (ptr).words[0] |= (v64 << 0) & 0x7ffffffffc;
}

#[inline]
pub fn endpoint_ptr_get_epQueue_tail(ptr: &endpoint_t) -> usize {
    let ret = ((ptr).words[0] & 0x7ffffffffcusize) >> 0;
    ret
}

#[inline]
pub fn endpoint_ptr_set_state(ptr: &mut endpoint_t, v64: usize) {
    (ptr).words[0] &= !0x3usize;
    (ptr).words[0] |= (v64 << 0) & 0x3;
}

#[inline]
pub fn endpoint_ptr_get_state(ptr: &endpoint_t) -> usize {
    let ret = ((ptr).words[0] & 0x3usize) >> 0;
    ret
}

#[inline]
pub fn cap_reply_cap_new(
    capReplyCanGrant: usize,
    capReplyMaster: usize,
    capTCBPtr: usize,
) -> cap_t {
    let mut cap = cap_t::default();
    cap.words[0] = 0
        | (capReplyCanGrant & 0x1usize) << 1
        | (capReplyMaster & 0x1usize) << 0
        | (cap_reply_cap & 0x1fusize) << 59;
    cap.words[1] = 0 | capTCBPtr << 0;
    cap
}

#[inline]
pub fn cap_reply_cap_get_capTCBPtr(cap: &cap_t) -> usize {
    let ret = (cap).words[1] & 0xffffffffffffffffusize;
    ret
}

#[inline]
pub fn cap_reply_cap_get_capReplyCanGrant(cap: &cap_t) -> usize {
    let ret = ((cap).words[0] & 0x2usize) >> 1;
    ret
}

#[inline]
pub fn cap_reply_cap_set_capReplyCanGrant(cap: &mut cap_t, v64: usize) {
    (cap).words[0] &= !0x2usize;
    (cap).words[0] |= (v64 << 1) & 0x2usize;
}

#[inline]
pub fn cap_reply_cap_get_capReplyMaster(cap: &cap_t) -> usize {
    let ret = ((cap).words[0] & 0x1usize) >> 0;
    ret
}

#[inline]
pub fn cap_thread_cap_new(capTCBPtr: usize) -> cap_t {
    let cap = cap_t {
        words: [
            0 | (cap_thread_cap & 0x1fusize) << 59 | (capTCBPtr & 0x7fffffffffusize) >> 0,
            0,
        ],
    };
    cap
}

#[inline]
pub fn cap_thread_cap_get_capTCBPtr(cap: &cap_t) -> usize {
    let ret: usize;
    ret = ((cap).words[0] & 0x7fffffffffusize) << 0;
    ret| 0xffffff8000000000
}

#[inline]
pub fn notification_ptr_get_ntfnBoundTCB(notification_ptr: &notification_t) -> usize {
    let ret: usize;
    ret = (notification_ptr).words[3] & 0x7fffffffffusize;
    ret| 0xffffff8000000000
}

#[inline]
pub fn notification_ptr_set_ntfnBoundTCB(ptr: &mut notification_t, v64: usize) {
    (ptr).words[3] &= !0x7fffffffffusize;
    (ptr).words[3] |= (v64 >> 0) & 0x7fffffffffusize;
}

#[inline]
pub fn notification_ptr_get_ntfnMsgIdentifier(notification_ptr: &notification_t) -> usize {
    let ret: usize;
    ret = (notification_ptr).words[2] & 0xffffffffffffffffusize;
    ret
}

#[inline]
pub fn notification_ptr_set_ntfnMsgIdentifier(ptr: &mut notification_t, v64: usize) {
    (ptr).words[2] &= !0xffffffffffffffffusize;
    (ptr).words[2] |= (v64 >> 0) & 0xffffffffffffffffusize;
}

#[inline]
pub fn notification_ptr_get_ntfnQueue_head(notification_ptr: &notification_t) -> usize {
    let ret: usize;
    ret = (notification_ptr).words[1] & 0x7fffffffffusize;
    ret| 0xffffff8000000000
}

#[inline]
pub fn notification_ptr_set_ntfnQueue_head(ptr: &mut notification_t, v64: usize) {
    (ptr).words[1] &= !0x7fffffffffusize;
    (ptr).words[1] |= (v64 >> 0) & 0x7fffffffffusize;
}

#[inline]
pub fn notification_ptr_get_ntfnQueue_tail(notification_ptr: &notification_t) -> usize {
    let ret: usize;
    ret = (notification_ptr).words[0] & 0xfffffffffe000000usize;
    ret| 0xffffff8000000000
}

#[inline]
pub fn notification_ptr_set_ntfnQueue_tail(ptr: &mut notification_t, v64: usize) {
    (ptr).words[0] &= !0xfffffffffe000000usize;
    (ptr).words[0] |= (v64 >> 0) & 0xfffffffffe000000usize;
}

#[inline]
pub fn notification_ptr_get_state(notification_ptr: &notification_t) -> usize {
    let ret: usize;
    ret = (notification_ptr).words[0] & 0x3usize;
    ret
}

#[inline]
pub fn notification_ptr_set_state(ptr: &mut notification_t, v64: usize) {
    (ptr).words[0] &= !0x3usize;
    (ptr).words[0] |= (v64 >> 0) & 0x3usize;
}

pub fn cap_notification_cap_new(
    capNtfnBadge: usize,
    capNtfnCanReceive: usize,
    capNtfnCanSend: usize,
    capNtfnPtr: usize,
) -> cap_t {
    let mut cap = cap_t::default();
    cap.words[0] = 0
        | (cap_notification_cap & 0x1fusize) << 59
        | (capNtfnCanReceive & 0x1usize) << 58
        | (capNtfnCanSend & 0x1usize) << 57
        | (capNtfnPtr & 0x7fffffffffusize) >> 0;
    cap.words[1] = 0 | capNtfnBadge << 0;
    cap
}

#[inline]
pub fn cap_notification_cap_get_capNtfnBadge(cap: &cap_t) -> usize {
    let ret = (cap).words[1] & 0xffffffffffffffffusize;
    ret
}

#[inline]
pub fn cap_notification_cap_set_capNtfnBadge(cap: &mut cap_t, v64: usize) {
    (cap).words[1] &= !0xffffffffffffffffusize;
    (cap).words[1] |= v64 & 0xffffffffffffffffusize;
}

#[inline]
pub fn cap_notification_cap_get_capNtfnCanReceive(cap: &cap_t) -> usize {
    let ret = (cap).words[0] & 0x400000000000000usize;
    ret
}

#[inline]
pub fn cap_notification_cap_set_capNtfnCanReceive(cap: &mut cap_t, v64: usize) {
    (cap).words[0] &= !0x400000000000000usize;
    (cap).words[0] |= v64 & 0x400000000000000usize;
}

#[inline]
pub fn cap_notification_cap_get_capNtfnCanSend(cap: &cap_t) -> usize {
    let ret = (cap).words[0] & 0x200000000000000usize;
    ret
}

#[inline]
pub fn cap_notification_cap_set_capNtfnCanSend(cap: &mut cap_t, v64: usize) {
    (cap).words[0] &= !0x200000000000000usize;
    (cap).words[0] |= v64 & 0x200000000000000usize;
}

#[inline]
pub fn cap_notification_cap_get_capNtfnPtr(cap: &cap_t) -> usize {
    let ret = (cap).words[0] & 0x7fffffffffusize;
    ret| 0xffffff8000000000
}

#[inline]
pub fn cap_notification_cap_set_capNtfnPtr(cap: &mut cap_t, v64: usize) {
    (cap).words[0] &= !0x7fffffffffusize;
    (cap).words[0] |= v64 & 0x7fffffffffusize;
}

#[inline]
pub fn cap_cnode_cap_new(
    capCNodeRadix: usize,
    capCNodeGuardSize: usize,
    capCNodeGuard: usize,
    capCNodePtr: usize,
) -> cap_t {
    let mut cap = cap_t::default();
    /* fail if user has passed bits that we will override */
    assert!(
        (capCNodeRadix & !0x3fusize)
            == (if true && (capCNodeRadix & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capCNodeGuardSize & !0x3fusize)
            == (if true && (capCNodeGuardSize & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );
    assert!(
        (capCNodePtr & !0x7ffffffffeusize)
            == (if true && (capCNodePtr & (1usize << 38)) != 0 {
                0xffffff8000000000
            } else {
                0
            })
    );
    assert!(
        (cap_tag_t::cap_cnode_cap as usize & !0x1fusize)
            == (if true && (cap_tag_t::cap_cnode_cap as usize & (1usize << 38)) != 0 {
                0x0
            } else {
                0
            })
    );

    cap.words[0] = 0
        | (capCNodeRadix & 0x3fusize) << 47
        | (capCNodeGuardSize & 0x3fusize) << 53
        | (capCNodePtr & 0x7ffffffffeusize) >> 1
        | (cap_tag_t::cap_cnode_cap as usize & 0x1fusize) << 59;
    cap.words[1] = 0 | capCNodeGuard << 0;
    cap
}

#[inline]
pub fn cap_irq_control_cap_new() -> cap_t {
    let mut cap = cap_t::default();

    cap.words[0] = 0 | (cap_irq_control_cap & 0x1fusize) << 59;
    cap.words[1] = 0;
    cap
}

#[inline]
pub fn cap_irq_handler_cap_new(capIRQ: usize) -> cap_t {
    let mut cap = cap_t::default();

    cap.words[0] = 0 | (cap_irq_handler_cap & 0x1fusize) << 59;
    cap.words[1] = 0 | (capIRQ & 0xfffusize) << 0;
    cap
}

#[inline]
pub fn cap_irq_handler_cap_get_capIRQ(cap: &cap_t) -> usize {
    let ret = (cap.words[1] & 0xfffusize) >> 0;
    ret
}
