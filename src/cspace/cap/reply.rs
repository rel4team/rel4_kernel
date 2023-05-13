use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct ReplyCap {
    cap: Cap,
}

impl ReplyCap {

    #[inline]
    pub fn new(capReplyCanGrant: usize, capReplyMaster: usize, capTCBPtr: usize) -> Self {
        let mut cap = Cap::default();
        cap.words[0] = 0
        | (capReplyCanGrant & 0x1usize) << 1
        | (capReplyMaster & 0x1usize) << 0
        | (CapTag::CapReplyCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0 | capTCBPtr << 0;
        Self { cap }
    }

    #[inline]
    pub fn get_tcb_ptr(&self) -> usize {
        self.cap.words[1] & 0xffffffffffffffffusize
    }

    #[inline]
    pub fn get_can_grant(&self) -> usize {
        (self.cap.words[0] & 0x2usize) >> 1
    }

    #[inline]
    pub fn set_can_grant(&mut self, v64: usize) {
        self.cap.words[0] &= !0x2usize;
        self.cap.words[0] |= (v64 << 1) & 0x2usize;
    }

    #[inline]
    pub fn get_master(&self) -> usize {
        (self.cap.words[0] & 0x1usize) >> 0
    }
    
}