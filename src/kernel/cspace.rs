

use crate::{structures::{
    lookupCapAndSlot_ret_t, lookupCap_ret_t
}, syscall::lookupSlotForCNodeOp};

use task_manager::*;

use common::structures::exception_t;
use cspace::interface::*;


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
