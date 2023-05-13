use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct NotificationCap {
    cap: Cap,
}

impl NotificationCap {

    #[inline]
    pub fn new(capNtfnBadge: usize, capNtfnCanReceive: usize, capNtfnCanSend: usize, capNtfnPtr: usize) -> Self {
        let mut cap = Cap::default();
        cap.words[0] = 0
        | (CapTag::CapNotificationCap as usize & 0x1fusize) << 59
        | (capNtfnCanReceive & 0x1usize) << 58
        | (capNtfnCanSend & 0x1usize) << 57
        | (capNtfnPtr & 0x7fffffffffusize) >> 0;
        cap.words[1] = 0 | capNtfnBadge << 0;
        Self { cap }
    }

    #[inline]
    pub fn get_badge(&self) -> usize {
        self.cap.words[1] & 0xffffffffffffffffusize
    }

    #[inline]
    pub fn set_badge(&mut self, v64: usize) {
        self.cap.words[1] &= !0xffffffffffffffffusize;
        self.cap.words[1] |= v64 & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_can_receive(&self) -> usize {
        (self.cap.words[0] & 0x400000000000000usize) >> 58
    }

    #[inline]
    pub fn set_can_receive(&mut self, v64: usize) {
        self.cap.words[0] &= !0x400000000000000usize;
        self.cap.words[0] |= (v64 << 58) & 0x400000000000000usize;
    }

    #[inline]
    pub fn get_can_send(&self) -> usize {
        (self.cap.words[0] & 0x200000000000000usize) >> 57
    }

    #[inline]
    pub fn set_can_send(&mut self, v64: usize) {
        self.cap.words[0] &= !0x200000000000000usize;
        self.cap.words[0] |= (v64 << 57) & 0x200000000000000usize;
    }

    #[inline]
    pub fn get_ptr(&self) -> usize {
        let mut ret = self.cap.words[0] & 0x7fffffffffusize;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_ptr(&mut self, v64: usize) {
        self.cap.words[0] &= !0x7fffffffffusize;
        self.cap.words[0] |= v64 & 0x7fffffffffusize;
    }



}