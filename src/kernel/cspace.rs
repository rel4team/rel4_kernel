

use crate::structures::{
    lookupCapAndSlot_ret_t, lookupCap_ret_t
};

use task_manager::*;
use common::structures::exception_t;
use cspace::interface::*;


#[no_mangle]
pub extern "C" fn lookupCapAndSlot(thread: *const tcb_t, cPtr: usize) -> lookupCapAndSlot_ret_t {
    // let lu_ret = lookupSlot(thread, cPtr);
    let lu_ret = unsafe {
        (*thread).lookup_slot(cPtr)
    };
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        let ret = lookupCapAndSlot_ret_t {
            status: lu_ret.status,
            slot: 0 as *mut cte_t,
            cap: cap_t::new_null_cap(),
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

