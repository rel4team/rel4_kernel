use crate::{sel4_config::seL4_MsgMaxLength, plus_define_bitfield};

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

plus_define_bitfield! {
    seL4_MessageInfo_t, 1, 0, 0, 0 => {
        new, 0 => {
            label, get_usize_label, set_label, 0, 12, 52, 0, false,
            capsUnwrapped, get_caps_unwrapped, set_caps_unwrapped, 0, 9, 3, 0, false,
            extraCaps, get_extra_caps, set_extra_caps, 0, 7, 2, 0, false,
            length, get_length, set_length, 0, 0, 7, 0, false
        }
    }
}

impl seL4_MessageInfo_t {
    #[inline]
    pub fn from_word(w: usize) -> Self {
        Self {
            words: [w]
        }
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
    pub fn get_label(&self) -> MessageLabel {
        unsafe {
            core::mem::transmute::<u8, MessageLabel>(self.get_usize_label() as u8)
        }
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
pub fn seL4_MessageInfo_ptr_set_capsUnwrapped(ptr: *mut seL4_MessageInfo_t, v64: usize) {
    unsafe {
        (*ptr).set_caps_unwrapped(v64)
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
