use common::structures::exception_t;

use crate::{cap::cap_t, structures::finaliseCap_ret};

/// 删除cap之后的一些扫尾操作，在delete之后调用
#[linkage = "weak"]
#[no_mangle]
pub fn post_cap_deletion(_cap: &cap_t) {
    panic!("Cannot find postCapDeletion!")
}

/// delete_all 耗时较长，可能需要允许中断抢占
#[linkage = "weak"]
#[no_mangle]
pub fn preemptionPoint() -> exception_t {
    panic!("Cannot find preemptionPoint!")
}

/// 不同的cap删除之后需要回收对应的内核对象资源，如取消ipc等，需要调用者实现
#[linkage = "weak"]
#[no_mangle]
pub fn finaliseCap(_cap: &cap_t, _final: bool, _exposed: bool) -> finaliseCap_ret {
    panic!("Cannot find finaliseCap!")
}