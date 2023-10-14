use super::sel4_config::*;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
pub struct seL4_IPCBuffer {
    pub tag: usize,
    pub msg: [usize; seL4_MsgMaxLength],
    pub userData: usize,
    pub caps_or_badges: [usize; seL4_MsgMaxExtraCaps],
    pub receiveCNode: usize,
    pub receiveIndex: usize,
    pub receiveDepth: usize,
}

impl seL4_IPCBuffer {
    pub fn get_extra_cptr(&self, i: usize) -> usize {
        self.caps_or_badges[i]
    }
}