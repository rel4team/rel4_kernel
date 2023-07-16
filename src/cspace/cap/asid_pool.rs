use core::intrinsics::likely;
use super::{cap_t, CapTag};

impl cap_t {
    
    #[inline]
    pub fn new_asid_pool_cap(capASIDBase: usize, capASIDPool: usize) -> Self {
        let mut cap = cap_t::default();
        cap.words[0] = 0
            | (CapTag::CapASIDPoolCap as usize & 0x1fusize) << 59
            | (capASIDBase & 0xffffusize) << 43
            | (capASIDPool & 0x7ffffffffcusize) >> 2;
        cap.words[1] = 0;
        cap
    }

    #[inline]
    pub fn get_asid_base(&self) -> usize {
        (self.words[0] & 0x7fff80000000000usize) >> 43
    }

    #[inline]
    pub fn get_asid_pool(&self) -> usize {
        let mut ret = (self.words[0] & 0x1fffffffffusize) << 2;
        if likely(!!(true && (ret & (1usize << (38))) != 0)) {
            ret |= 0xffffff8000000000;
        }
        ret
    }
}