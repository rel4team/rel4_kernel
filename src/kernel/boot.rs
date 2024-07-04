extern crate core;

use sel4_common::{
    fault::{lookup_fault_t, seL4_Fault_t},
    sel4_config::seL4_MsgMaxExtraCaps,
    utils::convert_to_option_mut_type_ref,
};
use sel4_cspace::interface::cte_t;

use crate::structures::{extra_caps_t, syscall_error_t};

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
    excaprefs: [0; seL4_MsgMaxExtraCaps],
};

#[inline]
pub fn get_extra_cap_by_index(index: usize) -> Option<&'static mut cte_t> {
    assert!(index < seL4_MsgMaxExtraCaps);
    unsafe { convert_to_option_mut_type_ref::<cte_t>(current_extra_caps.excaprefs[index] as usize) }
}
