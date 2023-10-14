

use super::{cap::{CapTag, cap_t}, interface::cte_t, cte::deriveCap_ret};


pub use super::cap::zombie::{
  Zombie_new,
  ZombieType_ZombieTCB
};

//cap_tag_t
pub const cap_endpoint_cap: usize = CapTag::CapEndpointCap as usize;
pub const cap_cnode_cap: usize = CapTag::CapCNodeCap as usize;
pub const cap_page_table_cap: usize = CapTag::CapPageTableCap as usize;

#[inline]
#[no_mangle]
pub fn isMDBParentOf() {
  panic!("should not be invoked!")
}


#[no_mangle]
pub fn deriveCap(_slot: *mut cte_t, _cap: &cap_t) -> deriveCap_ret {
    panic!("should not be invoked!")
}


#[inline]
pub fn cap_capType_equals(cap: &cap_t, cap_type_tag: usize) -> bool {
    cap.get_cap_type() as usize == cap_type_tag
}