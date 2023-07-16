use super::{cap_t, CapTag};

impl cap_t {

    #[inline]
    pub fn new_reply_cap(capReplyCanGrant: usize, capReplyMaster: usize, capTCBPtr: usize) -> Self {
        let mut cap = cap_t::default();
        cap.words[0] = 0
        | (capReplyCanGrant & 0x1usize) << 1
        | (capReplyMaster & 0x1usize) << 0
        | (CapTag::CapReplyCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0 | capTCBPtr << 0;
        cap
    }

    #[inline]
    pub fn get_reply_tcb_ptr(&self) -> usize {
        self.words[1] & 0xffffffffffffffffusize
    }

    #[inline]
    pub fn get_reply_can_grant(&self) -> usize {
        (self.words[0] & 0x2usize) >> 1
    }

    #[inline]
    pub fn set_reply_can_grant(&mut self, v64: usize) {
        self.words[0] &= !0x2usize;
        self.words[0] |= (v64 << 1) & 0x2usize;
    }

    #[inline]
    pub fn get_reply_master(&self) -> usize {
        (self.words[0] & 0x1usize) >> 0
    }
    
}

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