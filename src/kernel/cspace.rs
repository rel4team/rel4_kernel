use core::intrinsics::unlikely;

use crate::structures::{
    lookupCapAndSlot_ret_t, lookupCap_ret_t
};

use task_manager::*;

use common::{structures::{exception_t, lookup_fault_invalid_root_new, lookup_fault_depth_mismatch_new}, sel4_config::*};
use cspace::interface::*;
use super::boot::{current_lookup_fault, current_syscall_error};


#[no_mangle]
pub extern "C" fn lookupCapAndSlot(thread: *const tcb_t, cPtr: usize) -> lookupCapAndSlot_ret_t {
    let lu_ret = lookupSlot(thread, cPtr);
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        let ret = lookupCapAndSlot_ret_t {
            status: lu_ret.status,
            slot: 0 as *mut cte_t,
            cap: cap_null_cap_new(),
        };
        return ret;
    }
    unsafe {
        let ret = lookupCapAndSlot_ret_t {
            status: exception_t::EXCEPTION_NONE,
            slot: lu_ret.slot,
            cap: (*lu_ret.slot).cap.clone(),
        };
        ret
    }
}

pub fn lookupSlotForCNodeOp(
    isSource: bool,
    root: &cap_t,
    capptr: usize,
    depth: usize,
) -> lookupSlot_ret_t {
    let mut ret: lookupSlot_ret_t = lookupSlot_ret_t::default();
    if unlikely(cap_get_capType(&root) != cap_cnode_cap) {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = isSource as usize;
            current_lookup_fault = lookup_fault_invalid_root_new();
        }
        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
        return ret;
    }
    if unlikely(depth < 1 || depth > wordBits) {
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = wordBits;
        }
        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    let res_ret = rust_resolveAddressBits(&root, capptr, depth);

    if unlikely(ret.status != exception_t::EXCEPTION_NONE) {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = isSource as usize;
        }
        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
        return ret;
    }

    if unlikely(res_ret.bitsRemaining != 0) {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = isSource as usize;
            current_lookup_fault = lookup_fault_depth_mismatch_new(0, res_ret.bitsRemaining);
        }
        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
        return ret;
    }
    ret.slot = res_ret.slot;
    ret.status = exception_t::EXCEPTION_NONE;
    return ret;
}

#[no_mangle]
pub extern "C" fn lookupCap(thread: *const tcb_t, cPtr: usize) -> lookupCap_ret_t {
    let lu_ret = lookupSlot(thread, cPtr);
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        return lookupCap_ret_t {
            status: lu_ret.status,
            cap: cap_null_cap_new(),
        };
    }
    unsafe {
        lookupCap_ret_t {
            status: exception_t::EXCEPTION_NONE,
            cap: (*lu_ret.slot).cap.clone(),
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_lookupTargetSlot(
    root: &cap_t,
    capptr: usize,
    depth: usize,
) -> lookupSlot_ret_t {
    lookupSlotForCNodeOp(false, root, capptr, depth)
}

#[no_mangle]
pub extern "C" fn rust_lookupSourceSlot(
    root: &cap_t,
    capptr: usize,
    depth: usize,
) -> lookupSlot_ret_t {
    lookupSlotForCNodeOp(true, root, capptr, depth)
}

#[no_mangle]
pub extern "C" fn rust_lookupPivotSlot(
    root: &cap_t,
    capptr: usize,
    depth: usize,
) -> lookupSlot_ret_t {
    lookupSlotForCNodeOp(true, root, capptr, depth)
}
