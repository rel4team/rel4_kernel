use common::structures::exception_t;

use crate::{cap::{CapTag, cap_t}, interface::{cte_t, cte_insert}, cte::{insert_new_cap, deriveCap_ret}};
pub use super::cap::untyped::{
  cap_untyped_cap_get_capBlockSize, cap_untyped_cap_get_capFreeIndex, cap_untyped_cap_get_capIsDevice,
  cap_untyped_cap_get_capPtr, cap_untyped_cap_new, cap_untyped_cap_ptr_set_capFreeIndex, cap_untyped_cap_set_capFreeIndex,
};

pub use super::cap::endpoint::{
  cap_endpoint_cap_get_capCanGrant, cap_endpoint_cap_get_capCanGrantReply, cap_endpoint_cap_get_capCanReceive,
  cap_endpoint_cap_get_capCanSend, cap_endpoint_cap_get_capEPBadge, cap_endpoint_cap_get_capEPPtr,
};

pub use super::cap::zombie::{
  Zombie_new,
  ZombieType_ZombieTCB
};

pub use super::cap::page_table::{
  cap_page_table_cap_get_capPTBasePtr, cap_page_table_cap_get_capPTIsMapped, cap_page_table_cap_get_capPTMappedASID,
  cap_page_table_cap_get_capPTMappedAddress, cap_page_table_cap_new, cap_page_table_cap_ptr_set_capPTIsMapped,
  cap_page_table_cap_set_capPTIsMapped, cap_page_table_cap_set_capPTMappedASID, cap_page_table_cap_set_capPTMappedAddress,
};

pub use super::cap::frame::{
  cap_frame_cap_get_capFBasePtr, cap_frame_cap_get_capFIsDevice, cap_frame_cap_get_capFMappedASID, cap_frame_cap_get_capFMappedAddress,
  cap_frame_cap_get_capFSize, cap_frame_cap_get_capFVMRights, cap_frame_cap_new, cap_frame_cap_set_capFMappedASID,
  cap_frame_cap_set_capFMappedAddress, cap_frame_cap_set_capFVMRights,
};

pub use super::cap::asid_control::cap_asid_control_cap_new;

pub use super::cap::asid_pool::{
  cap_asid_pool_cap_get_capASIDBase, cap_asid_pool_cap_get_capASIDPool, cap_asid_pool_cap_new
};

pub use super::cap::domain::cap_domain_cap_new;

pub use super::cap::reply::{
  cap_reply_cap_get_capReplyCanGrant, cap_reply_cap_get_capReplyMaster, cap_reply_cap_get_capTCBPtr, cap_reply_cap_new,
  cap_reply_cap_set_capReplyCanGrant,
};

pub use super::cap::thread::{
  cap_thread_cap_get_capTCBPtr, cap_thread_cap_new
};

pub use super::cap::notification::{
  cap_notification_cap_get_capNtfnBadge, cap_notification_cap_get_capNtfnCanReceive, cap_notification_cap_get_capNtfnCanSend,
  cap_notification_cap_get_capNtfnPtr, cap_notification_cap_new, cap_notification_cap_set_capNtfnBadge,
  cap_notification_cap_set_capNtfnCanReceive, cap_notification_cap_set_capNtfnCanSend, cap_notification_cap_set_capNtfnPtr,
};

pub use super::cap::cnode::{
  cap_cnode_cap_get_capCNodePtr,
  cap_cnode_cap_get_capCNodeRadix, cap_cnode_cap_new
};


pub use super::cap::irq_handler::{
  cap_irq_handler_cap_get_capIRQ, cap_irq_handler_cap_new
};

pub use crate::cap_rights::rightsFromWord;

pub use super::cap::null::cap_null_cap_new;

pub use super::cte::{ cteDelete, cteDeleteOne, cteRevoke, };

pub use super::cap::updateCapData;


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

}


#[inline]
pub fn ensureNoChildren(slot: *mut cte_t) -> exception_t {
    unsafe {
        (& *slot).ensure_no_children()
    }
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
pub fn insertNewCap(parent: *mut cte_t, slot: *mut cte_t, cap: &cap_t) {
    unsafe {
        insert_new_cap(&mut *parent, &mut *slot, cap)
    }
}

#[inline]
pub fn cap_capType_equals(cap: &cap_t, cap_type_tag: usize) -> bool {
    cap.get_cap_type() as usize == cap_type_tag
}