use crate::{cap::cap_t, structures::finaliseCap_ret};

#[linkage = "weak"]
#[no_mangle]
pub fn post_cap_deletion(_cap: &cap_t) {
    panic!("Cannot find postCapDeletion!")
}

#[linkage = "weak"]
pub fn preemptionPoint() {
    panic!("Cannot find preemptionPoint!")
}

#[linkage = "weak"]
pub fn finaliseCap(_cap: &cap_t, _final: bool, _exposed: bool) -> finaliseCap_ret {
    panic!("Cannot find finaliseCap!")
}