use super::{cap_t, CapTag};

/// page_table cap相关字段和方法
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

#[inline]
pub fn cap_page_table_cap_new(capPTMappedASID: usize, capPTBasePtr: usize, capPTIsMapped: usize, capPTMappedAddress: usize) -> cap_t {
    cap_t::new_page_table_cap(capPTMappedASID, capPTBasePtr, capPTIsMapped, capPTMappedAddress)
}

#[inline]
pub fn cap_page_table_cap_get_capPTMappedASID(cap: &cap_t) -> usize {
    cap.get_pt_mapped_asid()
}

#[inline]
pub fn cap_page_table_cap_set_capPTMappedASID(cap: &mut cap_t, v64: usize) {
    cap.set_pt_mapped_asid(v64)
}

#[inline]
pub fn cap_page_table_cap_get_capPTBasePtr(cap: &cap_t) -> usize {
    cap.get_pt_base_ptr()
}

#[inline]
pub fn cap_page_table_cap_get_capPTIsMapped(cap: &cap_t) -> usize {
    cap.get_pt_is_mapped()
}

#[inline]
pub fn cap_page_table_cap_set_capPTIsMapped(cap: &mut cap_t, v64: usize) {
    cap.set_pt_is_mapped(v64)
}

#[inline]
pub fn cap_page_table_cap_ptr_set_capPTIsMapped(cap: &mut cap_t, v64: usize) {
    cap.set_pt_is_mapped(v64)
}
#[inline]
pub fn cap_page_table_cap_get_capPTMappedAddress(cap: &cap_t) -> usize {
    cap.get_pt_mapped_address()
}

#[inline]
pub fn cap_page_table_cap_set_capPTMappedAddress(cap: &mut cap_t, v64: usize) {
    cap.set_pt_mapped_address(v64)
}