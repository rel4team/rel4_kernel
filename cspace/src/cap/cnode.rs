use core::intrinsics::unlikely;

use super::{cap_t, CapTag};


impl cap_t {

    #[inline]
    pub fn new_cnode_cap( capCNodeRadix: usize, capCNodeGuardSize: usize, capCNodeGuard: usize, capCNodePtr: usize) -> Self {
        let mut cap = cap_t::default();
        assert_eq!((capCNodeRadix & !0x3fusize), (if true && (capCNodeRadix & (1usize << 38)) != 0 {
            0x0
        } else {
            0
        }));
        assert_eq!((capCNodeGuardSize & !0x3fusize), (if true && (capCNodeGuardSize & (1usize << 38)) != 0 {
            0x0
        } else {
            0
        }));
        assert_eq!((capCNodePtr & !0x7ffffffffeusize), (if true && (capCNodePtr & (1usize << 38)) != 0 {
            0xffffff8000000000
        } else {
            0
        }));
        assert_eq!((CapTag::CapCNodeCap as usize & !0x1fusize), (if true && (CapTag::CapCNodeCap as usize & (1usize << 38)) != 0 {
            0x0
        } else {
            0
        }));
        cap.words[0] = 0
        | (capCNodeRadix & 0x3fusize) << 47
        | (capCNodeGuardSize & 0x3fusize) << 53
        | (capCNodePtr & 0x7ffffffffeusize) >> 1
        | (CapTag::CapCNodeCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0 | capCNodeGuard << 0;
        cap
    }

    #[inline]
    pub fn get_cnode_guard(&self) -> usize {
         let mut ret = (self.words[1] & 0xffffffffffffffffusize) >> 0;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn set_cnode_guard(&mut self, v64: usize) {
        assert_eq!((((!0xffffffffffffffffusize >> 0) | 0x0) & v64), (if false && (v64 & (1usize << (38))) != 0 {
            0x0
        } else {
            0
        }));
        self.words[1] &= !0xffffffffffffffffusize;
        self.words[1] |= (v64 << 0) & 0xffffffffffffffffusize;
    }

    #[inline]
    pub fn get_cnode_guard_size(&self) -> usize {
        let mut ret = (self.words[0] & 0x7e0000000000000usize) >> 53;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn set_cnode_guard_size(&mut self, v64: usize) {
        assert_eq!((((!0x7e0000000000000usize >> 53) | 0x0) & v64), (if false && (v64 & (1usize << (38))) != 0 {
            0x0
        } else {
            0
        }));
        self.words[0] &= !0x7e0000000000000usize;
        self.words[0] |= (v64 << 53) & 0x7e0000000000000usize;
    }

    #[inline]
    pub fn get_cnode_radix(&self) -> usize {
        let mut ret = (self.words[0] & 0x1f800000000000usize) >> 47;
        /* Possibly sign extend */
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn get_cnode_ptr(&self) -> usize {
        let mut ret = (self.words[0] & 0x3fffffffffusize) << 1;
        /* Possibly sign extend */
        if (ret & (1 << 38)) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }
    
}

#[inline]
pub fn cap_cnode_cap_new(capCNodeRadix: usize, capCNodeGuardSize: usize, capCNodeGuard: usize, capCNodePtr: usize) -> cap_t {
    cap_t::new_cnode_cap(capCNodeRadix, capCNodeGuardSize, capCNodeGuard, capCNodePtr)
}


#[inline]
pub fn cap_cnode_cap_get_capCNodeRadix(cap: &cap_t) -> usize {
    cap.get_cnode_radix()
}

#[inline]
pub fn cap_cnode_cap_get_capCNodePtr(cap: &cap_t) -> usize {
    cap.get_cnode_ptr()
}