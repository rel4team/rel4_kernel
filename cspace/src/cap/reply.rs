use super::cap_t;

#[inline]
pub fn cap_reply_cap_get_capTCBPtr(cap: &cap_t) -> usize {
    cap.get_reply_tcb_ptr()
}