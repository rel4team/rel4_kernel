

use crate::{cap::{CapTag, cap_t}, interface::{cte_t, cte_insert}, cte::deriveCap_ret};
pub use super::cap::endpoint::{
  cap_endpoint_cap_get_capCanGrant, cap_endpoint_cap_get_capCanGrantReply, cap_endpoint_cap_get_capCanReceive,
  cap_endpoint_cap_get_capCanSend, cap_endpoint_cap_get_capEPPtr,
};

pub use super::cap::zombie::{
  Zombie_new,
  ZombieType_ZombieTCB
};

pub use super::cap::reply::{
  cap_reply_cap_get_capReplyCanGrant, cap_reply_cap_get_capReplyMaster, cap_reply_cap_get_capTCBPtr, cap_reply_cap_new,
  cap_reply_cap_set_capReplyCanGrant,
};

pub use super::cap::notification::{
  cap_notification_cap_get_capNtfnCanSend,
  cap_notification_cap_get_capNtfnPtr,
};


pub use super::cte::cteDeleteOne;


//cap_tag_t
pub const cap_null_cap: usize = CapTag::CapNullCap as usize;
pub const cap_untyped_cap: usize = CapTag::CapUntypedCap as usize;
pub const cap_endpoint_cap: usize = CapTag::CapEndpointCap as usize;
pub const cap_notification_cap: usize = CapTag::CapNotificationCap as usize;
pub const cap_reply_cap: usize = CapTag::CapReplyCap as usize;
pub const cap_cnode_cap: usize = CapTag::CapCNodeCap as usize;
pub const cap_thread_cap: usize = CapTag::CapThreadCap as usize;
pub const cap_irq_control_cap: usize = CapTag::CapIrqControlCap as usize;
pub const cap_irq_handler_cap: usize = CapTag::CapIrqHandlerCap as usize;
pub const cap_zombie_cap: usize = CapTag::CapZombieCap as usize;
pub const cap_domain_cap: usize = CapTag::CapDomainCap as usize;
pub const cap_frame_cap: usize = CapTag::CapFrameCap as usize;
pub const cap_page_table_cap: usize = CapTag::CapPageTableCap as usize;
pub const cap_asid_control_cap: usize = CapTag::CapASIDControlCap as usize;
pub const cap_asid_pool_cap: usize = CapTag::CapASIDPoolCap as usize;

#[inline]
pub fn cap_get_capType(cap: &cap_t) -> usize {
    cap.get_cap_type() as usize
}

#[inline]
#[no_mangle]
pub fn isMDBParentOf() {
  panic!("should not be invoked!")
}


#[inline]
pub fn cteInsert(newCap: &cap_t, srcSlot: *mut cte_t, destSlot: *mut cte_t) {
    unsafe {
        cte_insert(newCap, &mut *srcSlot, &mut *destSlot)
    }
}

#[inline]
#[no_mangle]
pub fn deriveCap(slot: *mut cte_t, cap: &cap_t) -> deriveCap_ret {
    unsafe {
        (&mut *slot).derive_cap(cap)
    }
}


#[inline]
pub fn cap_capType_equals(cap: &cap_t, cap_type_tag: usize) -> bool {
    cap.get_cap_type() as usize == cap_type_tag
}