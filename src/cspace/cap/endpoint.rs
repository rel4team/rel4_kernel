use core::intrinsics::{unlikely, likely};
use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct EndpointCap {
    cap: Cap,
}

impl EndpointCap {
    #[inline]
    pub fn new(capEPBadge: usize, capCanGrantReply: usize, capCanGrant: usize, capCanSend: usize, capCanReceive: usize, capEPPtr: usize) -> Self {
        let mut cap = Cap::default();

        /* fail if user has passed bits that we will override */
        assert!(
            (capCanGrantReply & !0x1usize)
                == (if true && (capCanGrantReply & (1usize << 38)) != 0 {
                    0x0
                } else {
                    0
                })
        );
        assert!(
            (capCanGrant & !0x1usize)
                == (if true && (capCanGrant & (1usize << 38)) != 0 {
                    0x0
                } else {
                    0
                })
        );
        assert!(
            (capCanSend & !0x1usize)
                == (if true && (capCanSend & (1usize << 38)) != 0 {
                    0x0
                } else {
                    0
                })
        );
        assert!(
            (capCanReceive & !0x1usize)
                == (if true && (capCanReceive & (1usize << 38)) != 0 {
                    0x0
                } else {
                    0
                })
        );
        assert!(
            (capEPPtr & !0x7fffffffffusize)
                == (if true && (capEPPtr & (1usize << 38)) != 0 {
                    0xffffff8000000000
                } else {
                    0
                })
        );

        cap.words[0] = 0
        | (capCanGrantReply & 0x1usize) << 58
        | (capCanGrant & 0x1usize) << 57
        | (capCanSend & 0x1usize) << 55
        | (capCanReceive & 0x1usize) << 56
        | (capEPPtr & 0x7fffffffffusize) >> 0
        | (CapTag::CapEndpointCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0 | capEPBadge << 0;
        Self { cap }
    }

    #[inline]
    pub fn get_badge(&self) -> usize {
        let mut ret = (self.cap.words[1] & 0xffffffffffffffffusize) >> 0;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        return ret;
    }

    #[inline]
    pub fn set_badge(&mut self, v64: usize) {
        assert!(
            (((!0xffffffffffffffffusize >> 0) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
    
        self.cap.words[1] &= !0xffffffffffffffffusize;
        self.cap.words[1] |= (v64 << 0) & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_can_grant_reply(&self) -> usize {
        let mut ret = (self.cap.words[0] & 0x400000000000000usize) >> 58;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        return ret;
    }

    #[inline]
    pub fn set_can_grant_reply(&mut self, v64: usize) {
        assert!(
            (((!0x400000000000000usize >> 58) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
        self.cap.words[0] &= !0x400000000000000usize;
        self.cap.words[0] |= (v64 << 58) & 0x400000000000000usize;
    }

    #[inline]
    pub fn get_can_grant(&self) -> usize {
        let mut ret = (self.cap.words[0] & 0x200000000000000usize) >> 57;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        return ret;
    }

    #[inline]
    pub fn set_can_grant(&mut self, v64: usize) {
        assert!(
            (((!0x200000000000000usize >> 57) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
    
        self.cap.words[0] &= !0x200000000000000usize;
        self.cap.words[0] |= (v64 << 57) & 0x200000000000000usize;
    }

    #[inline]
    pub fn get_can_receive(&self) -> usize {
        let mut ret = (self.cap.words[0] & 0x100000000000000usize) >> 56;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        return ret;
    }

    #[inline]
    pub fn set_can_receive(&mut self, v64: usize) {
        assert!(
            (((!0x100000000000000usize >> 56) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
    
        self.cap.words[0] &= !0x100000000000000usize;
        self.cap.words[0] |= (v64 << 56) & 0x100000000000000usize;
    }

    #[inline]
    pub fn get_can_send(&self) -> usize {
        let mut ret = (self.cap.words[0] & 0x80000000000000usize) >> 55;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        return ret;
    }

    #[inline]
    pub fn set_can_send(&mut self, v64: usize) {
        assert!(
            (((!0x80000000000000usize >> 55) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
    
        self.cap.words[0] &= !0x80000000000000usize;
        self.cap.words[0] |= (v64 << 55) & 0x80000000000000usize;
    }

    #[inline]
    pub fn get_ptr(&self) -> usize {
        let mut ret = (self.cap.words[0] & 0x7fffffffffusize) << 0;
        /* Possibly sign extend */
        if likely(!!(true && (ret & (1usize << (38))) != 0)) {
            ret |= 0xffffff8000000000;
        }
        ret
    }

}