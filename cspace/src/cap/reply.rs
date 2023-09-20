use super::cap_t;

#[inline]
pub fn cap_reply_cap_new(capReplyCanGrant: usize, capReplyMaster: usize, capTCBPtr: usize) -> cap_t {
    cap_t::new_reply_cap(capReplyCanGrant, capReplyMaster, capTCBPtr)
}

#[inline]
pub fn cap_reply_cap_get_capTCBPtr(cap: &cap_t) -> usize {
    cap.get_reply_tcb_ptr()
}

#[inline]
pub fn cap_reply_cap_get_capReplyCanGrant(cap: &cap_t) -> usize {
    cap.get_reply_can_grant()
}

#[inline]
pub fn cap_reply_cap_set_capReplyCanGrant(cap: &mut cap_t, v64: usize) {
    cap.set_reply_can_grant(v64)
}

#[inline]
pub fn cap_reply_cap_get_capReplyMaster(cap: &cap_t) -> usize {
    cap.get_reply_master()
}