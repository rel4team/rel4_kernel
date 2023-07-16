use super::{cap_t, CapTag};


impl cap_t {

    #[inline]
    pub fn new_asid_control_cap() -> Self {
        let mut cap = cap_t::default();
        cap.words[0] = 0 | (CapTag::CapASIDControlCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0;
        cap
    }
}