use crate::config::{
    seL4_Fault_CapFault, seL4_Fault_NullFault, seL4_Fault_UnknownSyscall, seL4_Fault_UserException,
    seL4_Fault_VMFault,
};

use common::structures::{notification_t, seL4_Fault_t};
use cspace::interface::*;
use crate::structures::endpoint_t;


//cap relevant

#[inline]
pub fn cap_get_max_free_index(cap: &cap_t) -> usize {
    let ans = cap_untyped_cap_get_capBlockSize(cap);
    let sel4_MinUntypedbits: usize = 4;
    (1usize << ans) - sel4_MinUntypedbits
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
