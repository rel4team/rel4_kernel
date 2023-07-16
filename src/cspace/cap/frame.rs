use super::{cap_t, CapTag};

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


#[inline]
pub fn cap_frame_cap_new(capFMappedASID: usize, capFBasePtr: usize, capFSize: usize, capFVMRights: usize, capFIsDevice: usize, capFMappedAddress: usize) -> cap_t {
    cap_t::new_frame_cap(capFMappedASID, capFBasePtr, capFSize, capFVMRights, capFIsDevice, capFMappedAddress)
}

#[inline]
pub fn cap_frame_cap_get_capFMappedASID(cap: &cap_t) -> usize {
    cap.get_frame_mapped_asid()
}

#[inline]
pub fn cap_frame_cap_set_capFMappedASID(cap: &mut cap_t, v64: usize) {
    cap.set_frame_mapped_asid(v64)
}

#[inline]
pub fn cap_frame_cap_get_capFBasePtr(cap: &cap_t) -> usize {
    cap.get_frame_base_ptr()
}

#[inline]
pub fn cap_frame_cap_get_capFSize(cap: &cap_t) -> usize {
    cap.get_frame_size()
}

#[inline]
pub fn cap_frame_cap_get_capFVMRights(cap: &cap_t) -> usize {
    cap.get_frame_vm_rights()
}

#[inline]
pub fn cap_frame_cap_set_capFVMRights(cap: &mut cap_t, v64: usize) {
    cap.set_frame_vm_rights(v64)
}

#[inline]
pub fn cap_frame_cap_get_capFIsDevice(cap: &cap_t) -> usize {
    cap.get_frame_is_device()
}

#[inline]
pub fn cap_frame_cap_get_capFMappedAddress(cap: &cap_t) -> usize {
    cap.get_frame_mapped_address()
}
#[inline]
pub fn cap_frame_cap_set_capFMappedAddress(cap: &mut cap_t, v64: usize) {
    cap.set_frame_mapped_address(v64)
}