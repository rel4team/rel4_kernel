//! This module contains the structures used in the seL4 microkernel.
//! For example, the `seL4_IPCBuffer` struct represents the IPC buffer used for inter-process communication in seL4.
//! The `exception_t` enum represents the different types of exceptions in the system.
use super::sel4_config::*;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Represents the different types of exceptions in the system.
pub enum exception_t {
    EXCEPTION_NONE,
    EXCEPTION_FAULT,
    EXCEPTION_LOOKUP_FAULT,
    EXCEPTION_SYSCALL_ERROR,
    EXCEPTION_PREEMTED,
    padding = isize::MAX - 1,
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Represents the IPC buffer used for inter-process communication in seL4.
pub struct seL4_IPCBuffer {
    /// The tag field of the IPC message.
    pub tag: usize,
    /// The message payload of the IPC message.
    pub msg: [usize; seL4_MsgMaxLength],
    /// User-defined data associated with the IPC message.
    pub userData: usize,
    /// Array of capabilities or badges associated with the IPC message.
    pub caps_or_badges: [usize; seL4_MsgMaxExtraCaps],
    /// The capability node where the IPC message is received.
    pub receiveCNode: usize,
    /// The index within the capability node where the IPC message is received.
    pub receiveIndex: usize,
    /// The depth of the capability node where the IPC message is received.
    pub receiveDepth: usize,
}

impl seL4_IPCBuffer {
    pub fn get_extra_cptr(&self, i: usize) -> usize {
        self.caps_or_badges[i]
    }
}
