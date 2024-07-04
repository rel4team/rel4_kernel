use crate::cap::cap_t;
use crate::structures::finaliseCap_ret;
use sel4_common::structures::exception_t;

extern "C" {
    pub fn Arch_finaliseCap(cap: &cap_t, final_: bool) -> finaliseCap_ret;

    pub fn finaliseCap(cap: &cap_t, _final: bool, _exposed: bool) -> finaliseCap_ret;

    pub fn post_cap_deletion(cap: &cap_t);

    pub fn preemptionPoint() -> exception_t;
}
