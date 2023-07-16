use super::{cap_t, CapTag};

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