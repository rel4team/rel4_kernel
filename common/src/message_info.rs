use crate::sel4_config::seL4_MsgMaxLength;

#[derive(Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
pub enum MessageLabel {
    InvalidInvocation                       = 0,
    UntypedRetype                           = 1,
    TCBReadRegisters                        = 2,
    TCBWriteRegisters                       = 3,
    TCBCopyRegisters                        = 4,
    TCBConfigure                            = 5,
    TCBSetPriority                          = 6,
    TCBSetMCPriority                        = 7,
    TCBSetSchedParams                       = 8,
    TCBSetIPCBuffer                         = 9,
    TCBSetSpace                             = 10,
    TCBSuspend                              = 11,
    TCBResume                               = 12,
    TCBBindNotification                     = 13,
    TCBUnbindNotification                   = 14,
    TCBSetTLSBase                           = 15,
    CNodeRevoke                             = 16,
    CNodeDelete                             = 17,
    CNodeCancelBadgedSends                  = 18,
    CNodeCopy                               = 19,
    CNodeMint                               = 20,
    CNodeMove                               = 21,
    CNodeMutate                             = 22,
    CNodeRotate                             = 23,
    CNodeSaveCaller                         = 24,
    IRQIssueIRQHandler                      = 25,
    IRQAckIRQ                               = 26,
    IRQSetIRQHandler                        = 27,
    IRQClearIRQHandler                      = 28,
    DomainSetSet                            = 29,
    RISCVPageTableMap                       = 30,
    RISCVPageTableUnmap                     = 31,
    RISCVPageMap                            = 32,
    RISCVPageUnmap                          = 33,
    RISCVPageGetAddress                     = 34,
    RISCVASIDControlMakePool                = 35,
    RISCVASIDPoolAssign                     = 36,
    RISCVIRQIssueIRQHandlerTrigger          = 37,
    nArchInvocationLabels                   = 38,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct seL4_MessageInfo_t {
    pub words: [usize; 1],
}

impl seL4_MessageInfo_t {
    #[inline]
    pub fn new(label: usize, capsUnwrapped: usize, extraCaps: usize, length: usize,) -> Self {
        let seL4_MessageInfo = seL4_MessageInfo_t {
            words: [0
                | (label & 0xfffffffffffffusize) << 12
                | (capsUnwrapped & 0x7usize) << 9
                | (extraCaps & 0x3usize) << 7
                | (length & 0x7fusize) << 0],
        };
        seL4_MessageInfo
    }

    #[inline]
    pub fn from_word(w: usize) -> Self {
        Self { words: [w] }
    }

    #[inline]
    pub fn from_word_security(w: usize) -> Self {
        let mut mi = Self::from_word(w);
        if mi.get_length() > seL4_MsgMaxLength {
            mi.set_length(seL4_MsgMaxLength);
        }
        mi
    }

    #[inline]
    pub fn to_word(&self) -> usize {
        self.words[0]
    }

    #[inline]
    pub fn get_length(&self) -> usize {
        self.words[0] & 0x7fusize
    }

    #[inline]
    pub fn set_length(&mut self, v64: usize) {
        self.words[0] &= !0x7fusize;
        self.words[0] |= v64 & 0x7f;
    }

    #[inline]
    pub fn get_extra_caps(&self) -> usize {
        (self.words[0] & 0x180usize) >> 7
    }

    #[inline]
    pub fn set_extra_caps(&mut self, v64: usize) {
        self.words[0] &= !0x180usize;
        self.words[0] |= (v64 << 7) & 0x180;
    }

    #[inline]
    pub fn get_caps_unwrapped(&self) -> usize {
        (self.words[0] & 0xe00usize) >> 9
    }

    #[inline]
    pub fn set_caps_unwrapped(&mut self, v64: usize) {
        self.words[0] &= !0xe00usize;
        self.words[0] |= (v64 << 9) & 0xe00;
    }

    #[inline]
    pub fn get_label(&self) -> MessageLabel {
        unsafe {
            core::mem::transmute::<u8, MessageLabel>(((self.words[0] & 0xfffffffffffff000usize) >> 12) as u8)
        }
    }

    #[inline]
    pub fn set_label(&mut self, v64: usize) {
        self.words[0] &= !0xfffffffffffff000usize;
        self.words[0] |= (v64 << 12) & 0xfffffffffffff000;
    }
}


#[inline]
pub fn wordFromMessageInfo(mi: seL4_MessageInfo_t) -> usize {
    mi.to_word()
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_length(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        (*ptr).get_length()
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_set_length(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).set_length(v64)
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_extraCaps(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        (*ptr).get_extra_caps()
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_set_extraCaps(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).set_extra_caps(v64)
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_capsUnwrapped(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        (*ptr).get_caps_unwrapped()
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_set_capsUnwrapped(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).set_caps_unwrapped(v64)
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_get_label(ptr: *const seL4_MessageInfo_t) -> usize {
    unsafe {
        (*ptr).get_label() as usize
    }
}

#[inline]
pub fn seL4_MessageInfo_ptr_set_label(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).set_label(v64)
    }
}

#[inline]
pub fn seL4_MessageInfo_new(
    label: usize,
    capsUnwrapped: usize,
    extraCaps: usize,
    length: usize,
) -> seL4_MessageInfo_t {
    seL4_MessageInfo_t::new(label, capsUnwrapped, extraCaps, length)
}

pub fn messageInfoFromWord_raw(w: usize) -> seL4_MessageInfo_t {
    seL4_MessageInfo_t::from_word(w)
}

pub fn messageInfoFromWord(w: usize) -> seL4_MessageInfo_t {
    seL4_MessageInfo_t::from_word_security(w)
}