use super::cap_t;


#[inline]
pub fn cap_notification_cap_get_capNtfnCanSend(cap: &cap_t) -> usize {
    cap.get_nf_can_send()
}


#[inline]
pub fn cap_notification_cap_get_capNtfnPtr(cap: &cap_t) -> usize {
    cap.get_nf_ptr()
}