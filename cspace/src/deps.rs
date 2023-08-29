use common::structures::exception_t;

use crate::{cap::cap_t, structures::finaliseCap_ret, interface::cte_t};

#[linkage = "weak"]
#[no_mangle]
pub fn post_cap_deletion(_cap: &cap_t) {
    panic!("Cannot find postCapDeletion!")
}

#[linkage = "weak"]
#[no_mangle]
pub fn preemptionPoint() -> exception_t {
    panic!("Cannot find preemptionPoint!")
}

#[linkage = "weak"]
#[no_mangle]
pub fn finaliseCap(_cap: &cap_t, _final: bool, _exposed: bool) -> finaliseCap_ret {
    panic!("Cannot find finaliseCap!")
}