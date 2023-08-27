extern crate core;

use common::structures::{lookup_fault_t, seL4_Fault_t};
use cspace::interface::cte_t;

use crate::{
    config::seL4_MsgMaxExtraCaps,
    structures::{
        extra_caps_t, syscall_error_t, 
    },
};

use task_manager::*;

#[link(name = "kernel_all.c")]
extern "C" {
    fn init_plat();
    fn tcbDebugAppend(action: *mut tcb_t);
}

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut active_irq: [usize; 1] = [0; 1];

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut current_lookup_fault: lookup_fault_t = lookup_fault_t { words: [0; 2] };

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut current_fault: seL4_Fault_t = seL4_Fault_t { words: [0; 2] };

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut current_syscall_error: syscall_error_t = syscall_error_t {
    invalidArgumentNumber: 0,
    invalidCapNumber: 0,
    rangeErrorMax: 0,
    rangeErrorMin: 0,
    memoryLeft: 0,
    failedLookupWasSource: 0,
    _type: 0,
};



#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut current_extra_caps: extra_caps_t = extra_caps_t {
    excaprefs: [0 as *mut cte_t; seL4_MsgMaxExtraCaps],
};

#[no_mangle]
pub extern "C" fn initIRQController(arr: *mut i32, size: usize) {
    unsafe {
        let data = core::slice::from_raw_parts_mut(arr, size);
        for i in 0..size {
            data[i] = 0;
        }
    }
}

