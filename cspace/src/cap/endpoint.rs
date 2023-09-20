
use super::cap_t;


#[inline]
pub fn cap_endpoint_cap_get_capEPBadge(cap: &cap_t) -> usize {
    cap.get_ep_badge()
}

#[inline]
pub fn cap_endpoint_cap_get_capCanGrantReply(cap: & cap_t) -> usize {
    cap.get_ep_can_grant_reply()
}


#[inline]
pub fn cap_endpoint_cap_get_capCanGrant(cap: &cap_t) -> usize {
    cap.get_ep_can_grant()
}

#[inline]
pub fn cap_endpoint_cap_get_capCanReceive(cap: &cap_t) -> usize {
    cap.get_ep_can_receive()
}

#[inline]
pub fn cap_endpoint_cap_get_capCanSend(cap: &cap_t) -> usize {
    cap.get_ep_can_send()
}

#[inline]
pub fn cap_endpoint_cap_get_capEPPtr(cap: &cap_t) -> usize {
    cap.get_ep_ptr()
}