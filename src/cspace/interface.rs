use super::{cap::{cap_t, CapTag}, mdb_node_t};


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
pub fn cap_null_cap_new() -> cap_t {
    cap_t::new_null_cap()
}

#[inline]
pub fn cap_untyped_cap_new(capFreeIndex: usize, capIsDevice: usize, capBlockSize: usize, capPtr: usize) -> cap_t {
    cap_t::new_untyped_cap(capFreeIndex, capIsDevice, capBlockSize, capPtr)
}

#[inline]
pub fn cap_untyped_cap_get_capIsDevice(cap: &cap_t) -> usize {
    cap.get_untyped_is_device()
}

#[inline]
pub fn cap_untyped_cap_get_capBlockSize(cap: &cap_t) -> usize {
    cap.get_untyped_block_size()
}
#[inline]
pub fn cap_untyped_cap_get_capFreeIndex(cap: &cap_t) -> usize {
    cap.get_untyped_free_index()
}

#[inline]
pub fn cap_untyped_cap_set_capFreeIndex(cap: &mut cap_t, v64: usize) {
   cap.set_untyped_free_index(v64)
}

#[inline]
pub fn cap_untyped_cap_ptr_set_capFreeIndex(cap: &mut cap_t, v64: usize) {
    cap.set_untyped_free_index(v64)
}

#[inline]
pub fn cap_untyped_cap_get_capPtr(cap: &cap_t) -> usize {
    cap.get_untyped_ptr()
}

#[inline]
pub fn cap_endpoint_cap_new(capEPBadge: usize, capCanGrantReply: usize, capCanGrant: usize, capCanSend: usize, capCanReceive: usize, capEPPtr: usize) -> cap_t {
    cap_t::new_endpoint_cap(capEPBadge, capCanGrantReply, capCanGrant, capCanSend, capCanReceive, capEPPtr)
}



#[inline]
pub fn cap_zombie_cap_new(capZombieID: usize, capZombieType: usize) -> cap_t {
    cap_t::new_zombie_cap(capZombieID, capZombieType)
}

#[inline]
pub fn cap_page_table_cap_new(capPTMappedASID: usize, capPTBasePtr: usize, capPTIsMapped: usize, capPTMappedAddress: usize) -> cap_t {
    cap_t::new_page_table_cap(capPTMappedASID, capPTBasePtr, capPTIsMapped, capPTMappedAddress)
}

#[inline]
pub fn cap_frame_cap_new(capFMappedASID: usize, capFBasePtr: usize, capFSize: usize, capFVMRights: usize, capFIsDevice: usize, capFMappedAddress: usize) -> cap_t {
    cap_t::new_frame_cap(capFMappedASID, capFBasePtr, capFSize, capFVMRights, capFIsDevice, capFMappedAddress)
}

#[inline]
pub fn cap_asid_control_cap_new() -> cap_t {
    cap_t::new_asid_control_cap()
}

#[inline]
pub fn cap_asid_pool_cap_new(capASIDBase: usize, capASIDPool: usize) -> cap_t {
    cap_t::new_asid_pool_cap(capASIDBase, capASIDPool)
}

#[inline]
pub fn cap_domain_cap_new() -> cap_t {
    cap_t::new_domain_cap()
}

#[inline]
pub fn cap_reply_cap_new(capReplyCanGrant: usize, capReplyMaster: usize, capTCBPtr: usize) -> cap_t {
    cap_t::new_reply_cap(capReplyCanGrant, capReplyMaster, capTCBPtr)
}

#[inline]
pub fn cap_thread_cap_new(capTCBPtr: usize) -> cap_t {
    cap_t::new_thread_cap(capTCBPtr)
}

#[inline]
pub fn cap_notification_cap_new(capNtfnBadge: usize, capNtfnCanReceive: usize, capNtfnCanSend: usize, capNtfnPtr: usize) -> cap_t {
    cap_t::new_notification_cap(capNtfnBadge, capNtfnCanReceive, capNtfnCanSend, capNtfnPtr)
}

#[inline]
pub fn cap_cnode_cap_new(capCNodeRadix: usize, capCNodeGuardSize: usize, capCNodeGuard: usize, capCNodePtr: usize) -> cap_t {
    cap_t::new_cnode_cap(capCNodeRadix, capCNodeGuardSize, capCNodeGuard, capCNodePtr)
}

#[inline]
pub fn cap_irq_control_cap_new() -> cap_t {
    cap_t::new_irq_control_cap()
}

#[inline]
pub fn cap_irq_handler_cap_new(capIRQ: usize) -> cap_t {
    cap_t::new_irq_handler_cap(capIRQ)
}



#[inline]
pub fn mdb_node_new(mdbNext: usize, mdbRevocable: usize, mdbFirstBadged: usize, mdbPrev: usize) -> mdb_node_t {
    mdb_node_t::new(mdbNext, mdbRevocable, mdbFirstBadged, mdbPrev)
}

#[inline]
pub fn mdb_node_get_mdbNext(mdb_node: &mdb_node_t) -> usize {
    mdb_node.get_next()
}

#[inline]
pub fn mdb_node_ptr_set_mdbNext(mdb_node: &mut mdb_node_t, v64: usize) {
    mdb_node.set_next(v64)
}

#[inline]
pub fn mdb_node_get_mdbRevocable(mdb_node: &mdb_node_t) -> usize {
    mdb_node.get_revocable()
}

#[inline]
pub fn mdb_node_get_mdbFirstBadged(mdb_node: &mdb_node_t) -> usize {
    mdb_node.get_first_badged()
}

#[inline]
pub fn mdb_node_set_mdbRevocable(mdb_node: &mut mdb_node_t, v64: usize) {
    mdb_node.set_revocable(v64)
}

#[inline]
pub fn mdb_node_set_mdbFirstBadged(mdb_node: &mut mdb_node_t, v64: usize) {
    mdb_node.set_first_badged(v64)
}

#[inline]
pub fn mdb_node_get_mdbPrev(mdb_node: &mdb_node_t) -> usize {
    mdb_node.get_prev()
}

#[inline]
pub fn mdb_node_set_mdbPrev(mdb_node: &mut mdb_node_t, v64: usize) {
    mdb_node.set_prev(v64)
}

#[inline]
pub fn mdb_node_ptr_set_mdbPrev(mdb_node: &mut mdb_node_t, v64: usize) {
    mdb_node.set_prev(v64)
}

#[inline]
pub fn cap_get_capType(cap: &cap_t) -> usize {
    (cap.words[0] >> 59) & 0x1fusize
}