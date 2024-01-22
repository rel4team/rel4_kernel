use super::sel4_config::seL4_MsgMaxLength;
use crate::plus_define_bitfield;

#[derive(Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
pub enum MessageLabel {
    InvalidInvocation                       = 0,
    UntypedRetype,
    TCBReadRegisters,
    TCBWriteRegisters,
    TCBCopyRegisters,
    TCBConfigure,
    TCBSetPriority,
    TCBSetMCPriority,
    TCBSetSchedParams,
    TCBSetIPCBuffer,
    TCBSetSpace,
    TCBSuspend,
    TCBResume,
    TCBBindNotification,
    TCBUnbindNotification,
    #[cfg(feature = "ENABLE_SMP")]
    TCBSetAffinity,
    TCBSetTLSBase,
    CNodeRevoke,
    CNodeDelete,
    CNodeCancelBadgedSends,
    CNodeCopy,
    CNodeMint,
    CNodeMove,
    CNodeMutate,
    CNodeRotate,
    CNodeSaveCaller,
    IRQIssueIRQHandler,
    IRQAckIRQ,
    IRQSetIRQHandler,
    IRQClearIRQHandler,
    DomainSetSet,
    #[cfg(feature = "ENABLE_UINTC")]
    UintrRegisterSender,
    #[cfg(feature = "ENABLE_UINTC")]
    UintrRegisterReceiver,
    RISCVPageTableMap,
    RISCVPageTableUnmap,
    RISCVPageMap,
    RISCVPageUnmap,
    RISCVPageGetAddress,
    RISCVASIDControlMakePool,
    RISCVASIDPoolAssign,
    RISCVIRQIssueIRQHandlerTrigger,
    nArchInvocationLabels,
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


pub fn messageInfoFromWord_raw(w: usize) -> seL4_MessageInfo_t {
    seL4_MessageInfo_t::from_word(w)
}
