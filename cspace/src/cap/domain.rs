use super::{cap_t, CapTag};

/// domain cap相关的字段和方法
impl cap_t {
    #[inline]
    pub fn new_domain_cap() -> Self {
        let mut cap = cap_t::default();
        cap.words[0] = 0 | (CapTag::CapDomainCap as usize & 0x1fusize) << 59;
        cap.words[1] = 0;
        cap
    }
}