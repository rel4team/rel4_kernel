use core::intrinsics::likely;
use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct ASIDPoolCap {
    cap: Cap,
}

impl ASIDPoolCap {
    
    #[inline]
    pub fn new(capASIDBase: usize, capASIDPool: usize) -> Self {
        let mut cap = Cap::default();
        cap.words[0] = 0
            | (CapTag::CapASIDPoolCap as usize & 0x1fusize) << 59
            | (capASIDBase & 0xffffusize) << 43
            | (capASIDPool & 0x7ffffffffcusize) >> 2;
        cap.words[1] = 0;
        Self { cap }
    }

    #[inline]
    pub fn get_asid_base(&self) -> usize {
        (self.cap.words[0] & 0x7fff80000000000usize) >> 43
    }

    #[inline]
    pub fn get_asid_pool(&self) -> usize {
        let mut ret = (self.cap.words[0] & 0x1fffffffffusize) << 2;
        if likely(!!(true && (ret & (1usize << (38))) != 0)) {
            ret |= 0xffffff8000000000;
        }
        ret
    }
}