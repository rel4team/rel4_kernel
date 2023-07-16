use super::{cap_t, CapTag};


impl cap_t {

    #[inline]
    pub fn new_page_table_cap(capPTMappedASID: usize, capPTBasePtr: usize, capPTIsMapped: usize, capPTMappedAddress: usize) -> Self {
        let mut cap = cap_t::default();

        cap.words[0] = 0
            | (CapTag::CapPageTableCap as usize & 0x1fusize) << 59
            | (capPTIsMapped & 0x1usize) << 39
            | (capPTMappedAddress & 0x7fffffffffusize) >> 0;
        cap.words[1] =
            0 | (capPTMappedASID & 0xffffusize) << 48 | (capPTBasePtr & 0x7f_ffff_ffffusize) << 9;

        cap
    }

    #[inline]
    pub fn get_pt_mapped_asid(&self) -> usize {
        (self.words[1] & 0xffff000000000000usize) >> 48
    }

    #[inline]
    pub fn set_pt_mapped_asid(&mut self, v64: usize) {
        self.words[1] &= !0xffff000000000000usize;
        self.words[1] |= (v64 << 48) & 0xffff000000000000usize;
    }

    #[inline]
    pub fn get_pt_base_ptr(&self) -> usize {
        let mut ret = (self.words[1] & 0xfffffffffe00usize) >> 9;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn get_pt_is_mapped(&self) -> usize {
        (self.words[0] & 0x8000000000usize) >> 39
    }

    #[inline]
    pub fn set_pt_is_mapped(&mut self, v64: usize) {
        self.words[0] &= !0x8000000000usize;
        self.words[0] |= (v64 << 39) & 0x8000000000usize;
    }

    #[inline]
    pub fn get_pt_mapped_address(&self) -> usize {
        let mut ret = (self.words[0] & 0x7fffffffffusize) << 0;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_pt_mapped_address(&mut self, v64: usize) {
        self.words[0] &= !0x7fffffffffusize;
        self.words[0] |= (v64 >> 0) & 0x7fffffffffusize;
    }
}