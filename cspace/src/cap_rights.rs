use common::MASK;
const seL4_CapRightsBits: usize = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct seL4_CapRights_t {
    pub word: usize,
}

impl seL4_CapRights_t {
    #[inline]
    pub fn from_word(word: usize) -> Self {
        Self { word }
    }

    #[inline]
    pub fn to_word(&self) -> usize {
        self.word & MASK!(seL4_CapRightsBits)
    }

    #[inline]
    pub fn get_allow_grant_reply(&self) -> usize {
        (self.word & & 0x8usize) >> 3
    }

    #[inline]
    pub fn get_allow_grant(&self) -> usize {
        (self.word & 0x4usize) >> 2
    }

    #[inline]
    pub fn get_allow_read(&self) -> usize {
        (self.word & 0x2usize) >> 1
    }
    
    #[inline]
    pub fn get_allow_write(&self) -> usize {
        (self.word & 0x1usize) >> 0
    }
}


#[inline]
pub fn rightsFromWord(w: usize) -> seL4_CapRights_t {
    seL4_CapRights_t::from_word(w)
}
