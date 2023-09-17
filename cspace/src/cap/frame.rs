use super::{cap_t, CapTag};

/// frame cap相关字段和方法
impl cap_t {
    #[inline]
    pub fn new_frame_cap(capFMappedASID: usize, capFBasePtr: usize, capFSize: usize, capFVMRights: usize, capFIsDevice: usize, capFMappedAddress: usize) -> Self {
        let mut cap = cap_t::default();
        cap.words[0] = 0
            | (CapTag::CapFrameCap as usize & 0x1fusize) << 59
            | (capFSize & 0x3usize) << 57
            | (capFVMRights & 0x3usize) << 55
            | (capFIsDevice & 0x1usize) << 54
            | (capFMappedAddress & 0x7fffffffffusize) >> 0;
        cap.words[1] =
            0 | (capFMappedASID & 0xffffusize) << 48 | (capFBasePtr & 0x7fffffffffusize) << 9;
        
        cap
    }

    #[inline]
    pub fn get_frame_mapped_asid(&self) -> usize {
        (self.words[1] & 0xffff000000000000usize) >> 48
    }

    #[inline]
    pub fn set_frame_mapped_asid(&mut self, v64: usize) {
        self.words[1] &= !0xffff000000000000usize;
        self.words[1] |= (v64 << 48) & 0xffff000000000000usize;
    }

    #[inline]
    pub fn get_frame_base_ptr(&self) -> usize {
        let mut ret = (self.words[1] & 0xfffffffffe00usize) >> 9;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn get_frame_size(&self) -> usize {
        (self.words[0] & 0x600000000000000usize) >> 57
    }

    #[inline]
    pub fn get_frame_vm_rights(&self) -> usize {
        (self.words[0] & 0x180000000000000usize) >> 55
    }

    #[inline]
    pub fn set_frame_vm_rights(&mut self, v64: usize) {
        self.words[0] &= !0x180000000000000usize;
        self.words[0] |= (v64 << 55) & 0x180000000000000usize;
    }

    #[inline]
    pub fn get_frame_is_device(&self) -> usize {
        (self.words[0] & 0x40000000000000usize) >> 54
    }

    #[inline]
    pub fn get_frame_mapped_address(&self) -> usize {
        let mut ret = (self.words[0] & 0x7fffffffffusize) << 0;
        if (ret & (1usize << 38)) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_frame_mapped_address(&mut self, v64: usize) {
        self.words[0] &= !0x7fffffffffusize;
        self.words[0] |= (v64 >> 0) & 0x7fffffffffusize;
    }
}