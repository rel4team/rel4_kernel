use crate::sel4_config::*;

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
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct lookup_fault_t {
    pub words: [usize; 2],
}

#[inline]
pub fn lookup_fault_get_lufType(lookup_fault: &lookup_fault_t) -> usize {
    (lookup_fault.words[0] >> 0) & 0x3usize
}

#[inline]
pub fn lookup_fault_invalid_root_new() -> lookup_fault_t {
    let lookup_fault = lookup_fault_t {
        words: [0 | (lookup_fault_invalid_root & 0x3usize) << 0, 0],
    };

    lookup_fault
}

#[inline]
pub fn lookup_fault_missing_capability_new(bitsLeft: usize) -> lookup_fault_t {
    let lookup_fault = lookup_fault_t {
        words: [
            0 | (bitsLeft & 0x7fusize) << 2 | (lookup_fault_missing_capability & 0x3usize) << 0,
            0,
        ],
    };

    lookup_fault
}

#[inline]
pub fn lookup_fault_missing_capability_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0x1fcusize) >> 2;
    ret
}

#[inline]
pub fn lookup_fault_depth_mismatch_new(bitsFound: usize, bitsLeft: usize) -> lookup_fault_t {
    let lookup_fault = lookup_fault_t {
        words: [
            0 | (bitsFound & 0x7fusize) << 9
                | (bitsLeft & 0x7fusize) << 2
                | (lookup_fault_depth_mismatch & 0x3usize) << 0,
            0,
        ],
    };

    lookup_fault
}

#[inline]
pub fn lookup_fault_depth_mismatch_get_bitsFound(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0xfe00usize) >> 9;
    ret
}

#[inline]
pub fn lookup_fault_depth_mismatch_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0x1fcusize) >> 2;
    ret
}

#[inline]
pub fn lookup_fault_guard_mismatch_new(
    guardFound: usize,
    bitsFound: usize,
    bitsLeft: usize,
) -> lookup_fault_t {
    let lookup_fault = lookup_fault_t {
        words: [
            0 | (bitsFound & 0x7fusize) << 9
                | (bitsLeft & 0x7fusize) << 2
                | (lookup_fault_depth_mismatch & 0x3usize) << 0,
            0 | guardFound << 0,
        ],
    };

    lookup_fault
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_guardFound(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[1] & 0xffffffffffffffffusize) >> 0;
    ret
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_bitsFound(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0xfe00usize) >> 9;
    ret
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    let ret = (lookup_fault.words[0] & 0x1fcusize) >> 2;
    ret
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct seL4_Fault_t {
    pub words: [usize; 2],
}

#[inline]
pub fn seL4_Fault_get_seL4_FaultType(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] >> 0) & 0xfusize
}

#[inline]
pub fn seL4_Fault_NullFault_new() -> seL4_Fault_t {
    seL4_Fault_t {
        words: [0 | (seL4_Fault_NullFault & 0xfusize) << 0, 0],
    }
}

#[inline]
pub fn seL4_Fault_CapFault_new(address: usize, inReceivePhase: usize) -> seL4_Fault_t {
    seL4_Fault_t {
        words: [
            0 | (inReceivePhase & 0x1usize) << 63 | (seL4_Fault_CapFault & 0xfusize) << 0,
            0 | address << 0,
        ],
    }
}

#[inline]
pub fn seL4_Fault_CapFault_get_address(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[1] & 0xffffffffffffffffusize) >> 0
}

#[inline]
pub fn seL4_Fault_CapFault_get_inReceivePhase(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0x8000000000000000usize) >> 63
}

#[inline]
pub fn seL4_Fault_UnknownSyscall_new(syscallNumber: usize) -> seL4_Fault_t {
    seL4_Fault_t {
        words: [
            0 | (seL4_Fault_UnknownSyscall & 0xfusize) << 0,
            0 | syscallNumber << 0,
        ],
    }
}

#[inline]
pub fn seL4_Fault_UnknownSyscall_get_syscallNumber(seL4_Fault: &seL4_Fault_t) -> usize {
    let ret = (seL4_Fault.words[1] & 0xffffffffffffffffusize) >> 0;
    ret
}

#[inline]
pub fn seL4_Fault_UserException_new(number: usize, code: usize) -> seL4_Fault_t {
    seL4_Fault_t {
        words: [
            0 | (number & 0xffffffffusize) << 32
                | (code & 0xfffffffusize) << 4
                | (seL4_Fault_UserException & 0xfusize) << 0,
            0,
        ],
    }
}

#[inline]
pub fn seL4_Fault_UserException_get_number(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0xffffffff00000000usize) >> 32
}

#[inline]
pub fn seL4_Fault_UserException_get_code(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0xfffffff0usize) >> 4
}

#[inline]
pub fn seL4_Fault_VMFault_new(address: usize, FSR: usize, instructionFault: bool) -> seL4_Fault_t {
    seL4_Fault_t {
        words: [
            0 | (FSR & 0x1fusize) << 27
                | (instructionFault as usize & 0x1usize) << 19
                | (seL4_Fault_VMFault & 0xfusize) << 0,
            0 | address << 0,
        ],
    }
}

#[inline]
pub fn seL4_Fault_VMFault_get_address(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[1] & 0xffffffffffffffffusize) >> 0
}

#[inline]
pub fn seL4_Fault_VMFault_get_FSR(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0xf8000000usize) >> 27
}

#[inline]
pub fn seL4_Fault_VMFault_get_instructionFault(seL4_Fault: &seL4_Fault_t) -> usize {
    (seL4_Fault.words[0] & 0x80000usize) >> 19
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