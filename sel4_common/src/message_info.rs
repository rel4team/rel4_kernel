//! This file contains the implementation of the `seL4_MessageInfo_t` struct and its associated methods.
//!
//! The `seL4_MessageInfo_t` struct represents a message info in the seL4 microkernel. It provides methods for creating, converting, and accessing the fields of a message info.
//!
//! # Examples
//!
//! Creating a new `seL4_MessageInfo_t` from a word:
//!
//! ```
//! let word = 0x12345678;
//! let message_info = seL4_MessageInfo_t::from_word(word);
//! ```
//!
//! Getting the label of the message:
//!
//! ```
//! let label = message_info.get_label();
//! ```

use super::sel4_config::seL4_MsgMaxLength;
use crate::plus_define_bitfield;

#[derive(Eq, PartialEq, Debug, Clone, Copy, PartialOrd, Ord)]
/// The label of a message.
pub enum MessageLabel {
    InvalidInvocation = 0,
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
    /// Creates a new `seL4_MessageInfo_t` from a word.
    #[inline]
    pub fn from_word(w: usize) -> Self {
        Self { words: [w] }
    }

    /// Creates a new `seL4_MessageInfo_t` from a word with security checks.
    #[inline]
    pub fn from_word_security(w: usize) -> Self {
        let mut mi = Self::from_word(w);
        if mi.get_length() > seL4_MsgMaxLength {
            mi.set_length(seL4_MsgMaxLength);
        }
        mi
    }

    /// Converts the `seL4_MessageInfo_t` to a word.
    #[inline]
    pub fn to_word(&self) -> usize {
        self.words[0]
    }

    /// Gets the label of the message.
    #[inline]
    pub fn get_label(&self) -> MessageLabel {
        unsafe { core::mem::transmute::<u8, MessageLabel>(self.get_usize_label() as u8) }
    }
}
