use common::MASK;
pub const seL4_CapRightsBits: usize = 4;

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
#[no_mangle]
pub fn rightsFromWord(w: usize) -> seL4_CapRights_t {
    seL4_CapRights_t::from_word(w)
}

#[inline]
pub fn wordFromRights(rights: &seL4_CapRights_t) -> usize {
   rights.to_word()
}

#[inline]
pub fn seL4_CapRights_get_capAllowGrantReply(rights: &seL4_CapRights_t) -> usize {
    rights.get_allow_grant_reply()
}

#[inline]
pub fn seL4_CapRights_get_capAllowGrant(rights: &seL4_CapRights_t) -> usize {
    rights.get_allow_grant()
}

#[inline]
pub fn seL4_CapRights_get_capAllowRead(rights: &seL4_CapRights_t) -> usize {
    rights.get_allow_read()
}

#[inline]
pub fn seL4_CapRights_get_capAllowWrite(rights: &seL4_CapRights_t) -> usize {
    rights.get_allow_write()
}