use super::cap_t;




#[inline]
pub fn cap_notification_cap_new(capNtfnBadge: usize, capNtfnCanReceive: usize, capNtfnCanSend: usize, capNtfnPtr: usize) -> cap_t {
    cap_t::new_notification_cap(capNtfnBadge, capNtfnCanReceive, capNtfnCanSend, capNtfnPtr)
}

#[inline]
pub fn cap_notification_cap_get_capNtfnBadge(cap: &cap_t) -> usize {
    cap.get_nf_badge()
}

#[inline]
pub fn cap_notification_cap_set_capNtfnBadge(cap: &mut cap_t, v64: usize) {
    cap.set_nf_badge(v64)
}

#[inline]
pub fn cap_notification_cap_get_capNtfnCanReceive(cap: &cap_t) -> usize {
    cap.get_nf_can_receive()
}

#[inline]
pub fn cap_notification_cap_set_capNtfnCanReceive(cap: &mut cap_t, v64: usize) {
    cap.set_nf_can_receive(v64)
}

#[inline]
pub fn cap_notification_cap_get_capNtfnCanSend(cap: &cap_t) -> usize {
    cap.get_nf_can_send()
}

#[inline]
pub fn cap_notification_cap_set_capNtfnCanSend(cap: &mut cap_t, v64: usize) {
    cap.set_nf_can_send(v64)
}

#[inline]
pub fn cap_notification_cap_get_capNtfnPtr(cap: &cap_t) -> usize {
    cap.get_nf_ptr()
}

#[inline]
pub fn cap_notification_cap_set_capNtfnPtr(cap: &mut cap_t, v64: usize) {
    cap.set_nf_ptr(v64)
}