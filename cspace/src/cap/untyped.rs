
use core::intrinsics::unlikely;

use super::{cap_t, CapTag};

/// untyped cap相关字段和方法
impl cap_t {
    #[inline]
    pub fn new_untyped_cap(capFreeIndex: usize, capIsDevice: usize, capBlockSize: usize, capPtr: usize) -> Self {
        let mut cap = cap_t::default();
        cap.words[0] = 0
        | (CapTag::CapUntypedCap as usize & 0x1fusize) << 59
        | (capPtr & 0x7fffffffffusize) >> 0;
        cap.words[1] = 0
            | (capFreeIndex & 0x7fffffffffusize) << 25
            | (capIsDevice & 0x1usize) << 6
            | (capBlockSize & 0x3fusize) << 0;
        cap
    }

    #[inline]
    pub fn get_untyped_is_device(&self) -> usize {
        let mut ret = (self.words[1] & 0x40usize) >> 6;
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn get_untyped_block_size(&self) -> usize {
        let mut ret = (self.words[1] & 0x3fusize) >> 0;
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn get_untyped_free_index(&self) -> usize {
        let mut ret = (self.words[1] & 0xfffffffffe000000usize) >> 25;
        if unlikely(!!(false && ((ret & (1usize << (38))) != 0))) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn set_untyped_free_index(&mut self, v64: usize) {
        assert_eq!((((!0xfffffffffe000000usize >> 25) | 0x0) & v64), (if false && (v64 & (1usize << (38))) != 0 {
            0x0
        } else {
            0
        }));
    
        self.words[1] &= !0xfffffffffe000000usize;
        self.words[1] |= (v64 << 25) & 0xfffffffffe000000usize;
    }

    #[inline]
    pub fn get_untyped_ptr(&self) -> usize {
        let mut ret = (self.words[0] & 0x7fffffffffusize) << 0;
        /* Possibly sign extend */
        if ((1 << 38) & ret) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }
}


#[inline]
pub fn cap_untyped_cap_new(capFreeIndex: usize, capIsDevice: usize, capBlockSize: usize, capPtr: usize) -> cap_t {
    cap_t::new_untyped_cap(capFreeIndex, capIsDevice, capBlockSize, capPtr)
}

#[inline]
pub fn cap_untyped_cap_get_capIsDevice(cap: &cap_t) -> usize {
    cap.get_untyped_is_device()
}

#[inline]
pub fn cap_untyped_cap_get_capBlockSize(cap: &cap_t) -> usize {
    cap.get_untyped_block_size()
}
#[inline]
pub fn cap_untyped_cap_get_capFreeIndex(cap: &cap_t) -> usize {
    cap.get_untyped_free_index()
}

#[inline]
pub fn cap_untyped_cap_set_capFreeIndex(cap: &mut cap_t, v64: usize) {
   cap.set_untyped_free_index(v64)
}

#[inline]
pub fn cap_untyped_cap_ptr_set_capFreeIndex(cap: &mut cap_t, v64: usize) {
    cap.set_untyped_free_index(v64)
}

#[inline]
pub fn cap_untyped_cap_get_capPtr(cap: &cap_t) -> usize {
    cap.get_untyped_ptr()
}

