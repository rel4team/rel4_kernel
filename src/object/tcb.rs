use crate::kernel::boot::{current_extra_caps, current_fault};
use task_manager::*;

use common::structures::exception_t;


pub fn lookup_extra_caps(thread: &tcb_t) -> exception_t {
    unsafe {
        match thread.lookup_extra_caps(&mut current_extra_caps.excaprefs) {
            Ok(()) =>{},
            Err(fault) => {
                current_fault = fault;
                return exception_t::EXCEPTION_LOOKUP_FAULT;
            },
        }
    }  
    return exception_t::EXCEPTION_NONE;
}