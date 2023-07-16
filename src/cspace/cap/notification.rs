use super::{cap_t, CapTag};


impl cap_t {

    #[inline]
    pub fn new_notification_cap(capNtfnBadge: usize, capNtfnCanReceive: usize, capNtfnCanSend: usize, capNtfnPtr: usize) -> Self {
        let mut cap = cap_t::default();
        cap.words[0] = 0
        | (CapTag::CapNotificationCap as usize & 0x1fusize) << 59
        | (capNtfnCanReceive & 0x1usize) << 58
        | (capNtfnCanSend & 0x1usize) << 57
        | (capNtfnPtr & 0x7fffffffffusize) >> 0;
        cap.words[1] = 0 | capNtfnBadge << 0;
        cap
    }

    #[inline]
    pub fn get_nf_badge(&self) -> usize {
        self.words[1] & 0xffffffffffffffffusize
    }

    #[inline]
    pub fn set_nf_badge(&mut self, v64: usize) {
        self.words[1] &= !0xffffffffffffffffusize;
        self.words[1] |= v64 & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_nf_can_receive(&self) -> usize {
        (self.words[0] & 0x400000000000000usize) >> 58
    }

    #[inline]
    pub fn set_nf_can_receive(&mut self, v64: usize) {
        self.words[0] &= !0x400000000000000usize;
        self.words[0] |= (v64 << 58) & 0x400000000000000usize;
    }

    #[inline]
    pub fn get_nf_can_send(&self) -> usize {
        (self.words[0] & 0x200000000000000usize) >> 57
    }

    #[inline]
    pub fn set_nf_can_send(&mut self, v64: usize) {
        self.words[0] &= !0x200000000000000usize;
        self.words[0] |= (v64 << 57) & 0x200000000000000usize;
    }

    #[inline]
    pub fn get_nf_ptr(&self) -> usize {
        let mut ret = self.words[0] & 0x7fffffffffusize;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_nf_ptr(&mut self, v64: usize) {
        self.words[0] &= !0x7fffffffffusize;
        self.words[0] |= v64 & 0x7fffffffffusize;
    }



}