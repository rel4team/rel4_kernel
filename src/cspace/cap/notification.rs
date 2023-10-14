use super::cap_t;

#[inline]
pub fn cap_notification_cap_get_capNtfnCanSend(cap: &cap_t) -> usize {
    cap.get_nf_can_send()
}