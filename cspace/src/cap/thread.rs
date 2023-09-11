use super::{cap_t, CapTag};

/// thread cap相关字段和方法
impl cap_t {
    #[inline]
    pub fn new_thread_cap(capTCBPtr: usize) -> Self {
        let cap = cap_t {
            words: [
                0 | (CapTag::CapThreadCap as usize & 0x1fusize) << 59 | (capTCBPtr & 0x7fffffffffusize) >> 0,
                0,
            ],
        };
        cap
    }

    #[inline]
    pub fn get_tcb_ptr(&self) -> usize {
        let mut ret = (self.words[0] & 0x7fffffffffusize) << 0;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }
}

#[inline]
pub fn cap_thread_cap_new(capTCBPtr: usize) -> cap_t {
    cap_t::new_thread_cap(capTCBPtr)
}

#[inline]
pub fn cap_thread_cap_get_capTCBPtr(cap: &cap_t) -> usize {
    cap.get_tcb_ptr()
}
