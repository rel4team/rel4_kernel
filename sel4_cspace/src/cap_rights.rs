use sel4_common::plus_define_bitfield;

plus_define_bitfield! {
    seL4_CapRights_t, 1, 0, 0, 0 => {
        new, 0 => {
            allow_grant_reply, get_allow_grant_reply, set_allow_grant_reply, 0, 3, 1, 0, false,
            allow_grant, get_allow_grant, set_allow_grant, 0, 2, 1, 0, false,
            allow_read, get_allow_read, set_allow_read, 0, 1, 1, 0, false,
            allow_write, get_allow_write, set_allow_write, 0, 0, 1, 0, false
        }
    }
}

impl seL4_CapRights_t {
    #[inline]
    pub fn from_word(word: usize) -> Self {
        Self { words: [word] }
    }
}
