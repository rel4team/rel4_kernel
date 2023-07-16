use crate::config::{
    lookup_fault_depth_mismatch, lookup_fault_invalid_root, lookup_fault_missing_capability,
    seL4_Fault_CapFault, seL4_Fault_NullFault, seL4_Fault_UnknownSyscall, seL4_Fault_UserException,
    seL4_Fault_VMFault,
};

use crate::cspace::interface::*;
use crate::cspace::cap::cap_t;
use crate::cspace::mdb_node_t;
use crate::structures::{
    cap_tag_t, endpoint_t, lookup_fault_t, notification_t, pte_t, seL4_Fault_t,
    thread_state_t,
};

//CSpace relevant
use core::intrinsics::{likely, unlikely};

use crate::MASK;

//zombie config
pub const wordRadix: usize = 6;

//cap relevant

#[inline]
pub fn cap_get_max_free_index(cap: &cap_t) -> usize {
    let ans = cap_untyped_cap_get_capBlockSize(cap);
    let sel4_MinUntypedbits: usize = 4;
    (1usize << ans) - sel4_MinUntypedbits
}


#[inline]
pub fn pte_ptr_get_ppn(pte_ptr: *const pte_t) -> usize {
    unsafe {
        let ret = ((*pte_ptr).words[0] & 0x3f_ffff_ffff_fc00usize) >> 10;
        ret
    }
}
#[inline]
pub fn pte_ptr_get_execute(pte_ptr: *const pte_t) -> usize {
    unsafe {
        let ret = ((*pte_ptr).words[0] & 0x8usize) >> 3;
        ret
    }
}

#[inline]
pub fn pte_ptr_get_write(pte_ptr: *const pte_t) -> usize {
    unsafe {
        let ret = ((*pte_ptr).words[0] & 0x4usize) >> 2;
        ret
    }
}

#[inline]
pub fn pte_ptr_get_read(pte_ptr: *const pte_t) -> usize {
    unsafe {
        let ret = ((*pte_ptr).words[0] & 0x2usize) >> 1;
        ret
    }
}

#[inline]
pub fn pte_ptr_get_valid(pte_ptr: *const pte_t) -> usize {
    unsafe {
        let ret = ((*pte_ptr).words[0] & 0x1usize) >> 0;
        ret
    }
}

#[inline]
pub fn thread_state_new() -> thread_state_t {
    let state = thread_state_t { words: [0; 3] };
    state
}

#[inline]
pub fn thread_state_get_blockingIPCBadge(thread_state_ptr: &thread_state_t) -> usize {
    let mut ret = (thread_state_ptr).words[2] & 0xffffffffffffffffusize;
    if (ret & (1usize << (38))) != 0 {
        ret |= 0xffffff8000000000;
    }
    ret
}

#[inline]
pub fn thread_state_set_blockingIPCBadge(mut thread_state_ptr: &mut thread_state_t, v64: usize) {
    (thread_state_ptr).words[2] &= !0xffffffffffffffffusize;
    (thread_state_ptr).words[2] |= v64 & 0xffffffffffffffffusize;
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
    let mut ret = ((thread_state_ptr).words[0] & 0x7ffffffff0usize) << 0;
    if (ret & (1usize << (38))) != 0 {
        ret |= 0xffffff8000000000;
    }
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
#[no_mangle]
pub fn thread_state_set_tsType(thread_state_ptr: &mut thread_state_t, v64: usize) {
    (thread_state_ptr).words[0] &= !0xfusize;
    (thread_state_ptr).words[0] |= v64 & 0xfusize;
}


#[inline]
pub fn endpoint_ptr_set_epQueue_head(ptr: *mut endpoint_t, v64: usize) {
    unsafe {
        (*ptr).words[1] &= !0xffffffffffffffffusize;
        (*ptr).words[1] |= (v64 << 0) & 0xffffffffffffffff;
    }
}

#[inline]
pub fn endpoint_ptr_get_epQueue_head(ptr: *const endpoint_t) -> usize {
    unsafe {
        let ret = ((*ptr).words[1] & 0xffffffffffffffffusize) >> 0;
        ret
    }
}

#[inline]
pub fn endpoint_ptr_set_epQueue_tail(ptr: *mut endpoint_t, v64: usize) {
    unsafe {
        (*ptr).words[0] &= !0x7ffffffffcusize;
        (*ptr).words[0] |= (v64 << 0) & 0x7ffffffffc;
    }
}

#[inline]
pub fn endpoint_ptr_get_epQueue_tail(ptr: *const endpoint_t) -> usize {
    unsafe {
        let mut ret = ((*ptr).words[0] & 0x7ffffffffcusize) >> 0;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }
}

#[inline]
pub fn endpoint_ptr_set_state(ptr: *mut endpoint_t, v64: usize) {
    unsafe {
        (*ptr).words[0] &= !0x3usize;
        (*ptr).words[0] |= (v64 << 0) & 0x3;
    }
}

#[inline]
pub fn endpoint_ptr_get_state(ptr: *const endpoint_t) -> usize {
    unsafe {
        let ret = ((*ptr).words[0] & 0x3usize) >> 0;
        ret
    }
}

#[inline]
pub fn notification_ptr_get_ntfnBoundTCB(notification_ptr: *const notification_t) -> usize {
    let mut ret: usize;
    unsafe {
        ret = (*notification_ptr).words[3] & 0x7fffffffffusize;
    }
    if (ret & (1usize << (38))) != 0 {
        ret |= 0xffffff8000000000;
    }
    ret
}

#[inline]
pub fn notification_ptr_set_ntfnBoundTCB(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).words[3] &= !0x7fffffffffusize;
        (*ptr).words[3] |= (v64 >> 0) & 0x7fffffffffusize;
    }
}

#[inline]
pub fn notification_ptr_get_ntfnMsgIdentifier(notification_ptr: *const notification_t) -> usize {
    let ret: usize;
    unsafe {
        ret = (*notification_ptr).words[2] & 0xffffffffffffffffusize;
    }
    ret
}

#[inline]
pub fn notification_ptr_set_ntfnMsgIdentifier(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).words[2] &= !0xffffffffffffffffusize;
        (*ptr).words[2] |= (v64 >> 0) & 0xffffffffffffffffusize;
    }
}

#[inline]
pub fn notification_ptr_get_ntfnQueue_head(notification_ptr: *const notification_t) -> usize {
    let mut ret: usize;
    unsafe {
        ret = (*notification_ptr).words[1] & 0x7fffffffffusize;
    }
    if (ret & (1usize << (38))) != 0 {
        ret |= 0xffffff8000000000;
    }
    ret
}

#[inline]
pub fn notification_ptr_set_ntfnQueue_head(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).words[1] &= !0x7fffffffffusize;
        (*ptr).words[1] |= (v64 >> 0) & 0x7fffffffff;
    }
}

#[inline]
pub fn notification_ptr_get_ntfnQueue_tail(notification_ptr: *const notification_t) -> usize {
    let mut ret: usize;
    unsafe {
        ret = ((*notification_ptr).words[0] & 0xfffffffffe000000usize) >> 25;
    }
    if (ret & (1usize << (38))) != 0 {
        ret |= 0xffffff8000000000;
    }
    ret
}

#[inline]
pub fn notification_ptr_set_ntfnQueue_tail(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).words[0] &= !0xfffffffffe000000usize;
        (*ptr).words[0] |= (v64 << 25) & 0xfffffffffe000000usize;
    }
}

#[inline]
pub fn notification_ptr_get_state(notification_ptr: *const notification_t) -> usize {
    let ret: usize;
    unsafe {
        ret = (*notification_ptr).words[0] & 0x3usize;
    }
    ret
}

#[inline]
pub fn notification_ptr_set_state(ptr: *mut notification_t, v64: usize) {
    unsafe {
        (*ptr).words[0] &= !0x3usize;
        (*ptr).words[0] |= (v64 >> 0) & 0x3usize;
    }
}

#[inline]
pub fn lookup_fault_get_lufType(lookup_fault: &lookup_fault_t) -> usize {
    (lookup_fault.words[0] >> 0) & 0x3usize
}

#[inline]
pub fn lookup_fault_invalid_root_new() -> lookup_fault_t {
    let lookup_fault = lookup_fault_t {
        words: [0 | (lookup_fault_invalid_root & 0x3usize) << 0, 0],
    };

    lookup_fault
}

#[inline]
pub fn lookup_fault_missing_capability_new(bitsLeft: usize) -> lookup_fault_t {
    let lookup_fault = lookup_fault_t {
        words: [
            0 | (bitsLeft & 0x7fusize) << 2 | (lookup_fault_missing_capability & 0x3usize) << 0,
            0,
        ],
    };

    lookup_fault
}

#[inline]
pub fn lookup_fault_missing_capability_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0x1fcusize) >> 2;
    ret
}

#[inline]
pub fn lookup_fault_depth_mismatch_new(bitsFound: usize, bitsLeft: usize) -> lookup_fault_t {
    let lookup_fault = lookup_fault_t {
        words: [
            0 | (bitsFound & 0x7fusize) << 9
                | (bitsLeft & 0x7fusize) << 2
                | (lookup_fault_depth_mismatch & 0x3usize) << 0,
            0,
        ],
    };

    lookup_fault
}

#[inline]
pub fn lookup_fault_depth_mismatch_get_bitsFound(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0xfe00usize) >> 9;
    ret
}

#[inline]
pub fn lookup_fault_depth_mismatch_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0x1fcusize) >> 2;
    ret
}

#[inline]
pub fn lookup_fault_guard_mismatch_new(
    guardFound: usize,
    bitsFound: usize,
    bitsLeft: usize,
) -> lookup_fault_t {
    let lookup_fault = lookup_fault_t {
        words: [
            0 | (bitsFound & 0x7fusize) << 9
                | (bitsLeft & 0x7fusize) << 2
                | (lookup_fault_depth_mismatch & 0x3usize) << 0,
            0 | guardFound << 0,
        ],
    };

    lookup_fault
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_guardFound(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[1] & 0xffffffffffffffffusize) >> 0;
    ret
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_bitsFound(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0xfe00usize) >> 9;
    ret
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0x1fcusize) >> 2;
    ret
}

#[inline]
pub fn seL4_Fault_get_seL4_FaultType(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] >> 0) & 0xfusize
}

#[inline]
pub fn seL4_Fault_NullFault_new() -> seL4_Fault_t {
    seL4_Fault_t {
        words: [0 | (seL4_Fault_NullFault & 0xfusize) << 0, 0],
    }
}

#[inline]
pub fn seL4_Fault_CapFault_new(address: usize, inReceivePhase: usize) -> seL4_Fault_t {
    seL4_Fault_t {
        words: [
            0 | (inReceivePhase & 0x1usize) << 63 | (seL4_Fault_CapFault & 0xfusize) << 0,
            0 | address << 0,
        ],
    }
}

#[inline]
pub fn seL4_Fault_CapFault_get_address(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[1] & 0xffffffffffffffffusize) >> 0
}

#[inline]
pub fn seL4_Fault_CapFault_get_inReceivePhase(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0x8000000000000000usize) >> 63
}

#[inline]
pub fn seL4_Fault_UnknownSyscall_new(syscallNumber: usize) -> seL4_Fault_t {
    seL4_Fault_t {
        words: [
            0 | (seL4_Fault_UnknownSyscall & 0xfusize) << 0,
            0 | syscallNumber << 0,
        ],
    }
}

#[inline]
pub fn seL4_Fault_UnknownSyscall_get_syscallNumber(seL4_Fault: &seL4_Fault_t) -> usize {
    let ret = (seL4_Fault.words[1] & 0xffffffffffffffffusize) >> 0;
    ret
}

#[inline]
pub fn seL4_Fault_UserException_new(number: usize, code: usize) -> seL4_Fault_t {
    seL4_Fault_t {
        words: [
            0 | (number & 0xffffffffusize) << 32
                | (code & 0xfffffffusize) << 4
                | (seL4_Fault_UserException & 0xfusize) << 0,
            0,
        ],
    }
}

#[inline]
pub fn seL4_Fault_UserException_get_number(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0xffffffff00000000usize) >> 32
}

#[inline]
pub fn seL4_Fault_UserException_get_code(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0xfffffff0usize) >> 4
}

#[inline]
pub fn seL4_Fault_VMFault_new(address: usize, FSR: usize, instructionFault: bool) -> seL4_Fault_t {
    seL4_Fault_t {
        words: [
            0 | (FSR & 0x1fusize) << 27
                | (instructionFault as usize & 0x1usize) << 19
                | (seL4_Fault_VMFault & 0xfusize) << 0,
            0 | address << 0,
        ],
    }
}

#[inline]
pub fn seL4_Fault_VMFault_get_address(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[1] & 0xffffffffffffffffusize) >> 0
}

#[inline]
pub fn seL4_Fault_VMFault_get_FSR(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0xf8000000usize) >> 27
}

#[inline]
pub fn seL4_Fault_VMFault_get_instructionFault(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0x80000usize) >> 19
}

