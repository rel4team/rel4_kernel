use super::{Cap, CapTag};

#[derive(Clone, Copy, Debug)]
pub struct ThreadCap {
    cap: Cap,
}

impl ThreadCap {

    #[inline]
    pub fn new(capTCBPtr: usize) -> Self {
        let cap = Cap {
            words: [
                0 | (CapTag::CapThreadCap as usize & 0x1fusize) << 59 | (capTCBPtr & 0x7fffffffffusize) >> 0,
                0,
            ],
        };
        Self { cap }
    }

    #[inline]
    pub fn get_tcb_ptr(&self) -> usize {
        let mut ret = (self.cap.words[0] & 0x7fffffffffusize) << 0;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }
}