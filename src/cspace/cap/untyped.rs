
use core::intrinsics::unlikely;
use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct UntypedCap {
    cap: Cap,
}

impl UntypedCap {

    #[inline]
    pub fn new(capFreeIndex: usize, capIsDevice: usize, capBlockSize: usize, capPtr: usize) -> Self {
        let mut cap = Cap::default();
        cap.words[0] = 0
        | (CapTag::CapUntypedCap as usize & 0x1fusize) << 59
        | (capPtr & 0x7fffffffffusize) >> 0;
        cap.words[1] = 0
            | (capFreeIndex & 0x7fffffffffusize) << 25
            | (capIsDevice & 0x1usize) << 6
            | (capBlockSize & 0x3fusize) << 0;
        UntypedCap { cap }
    }

    #[inline]
    pub fn is_device(&self) -> usize {
        let mut ret = (self.cap.words[1] & 0x40usize) >> 6;
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn get_block_size(&self) -> usize {
        let mut ret = (self.cap.words[1] & 0x3fusize) >> 0;
        if unlikely(!!(false && (ret & (1usize << (38))) != 0)) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn get_free_index(&self) -> usize {
        let mut ret = (self.cap.words[1] & 0xfffffffffe000000usize) >> 25;
        if unlikely(!!(false && ((ret & (1usize << (38))) != 0))) {
            ret |= 0x0;
        }
        ret
    }

    #[inline]
    pub fn set_free_index(&mut self, v64: usize) {
        assert!(
            (((!0xfffffffffe000000usize >> 25) | 0x0) & v64)
                == (if false && (v64 & (1usize << (38))) != 0 {
                    0x0
                } else {
                    0
                })
        );
    
        self.cap.words[1] &= !0xfffffffffe000000usize;
        self.cap.words[1] |= (v64 << 25) & 0xfffffffffe000000usize;
    }

    #[inline]
    pub fn get_ptr(&self) -> usize {
        let mut ret = (self.cap.words[0] & 0x7fffffffffusize) << 0;
        /* Possibly sign extend */
        if ((1 << 38) & ret) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }






}

