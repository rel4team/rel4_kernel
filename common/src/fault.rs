
#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct seL4_Fault_t {
    pub words: [usize; 2],
}
#[derive(Clone, Copy, Debug)]
pub enum FaultType {
    NullFault = 0,
    CapFault = 1,
    UnknownSyscall = 2,
    UserException = 3,
    VMFault = 5,
}

pub const seL4_Fault_NullFault: usize = FaultType::NullFault as usize;
pub const seL4_Fault_CapFault: usize = FaultType::CapFault as usize;
pub const seL4_Fault_UnknownSyscall: usize = FaultType::UnknownSyscall as usize;
pub const seL4_Fault_UserException: usize = FaultType::UserException as usize;
pub const seL4_Fault_VMFault: usize = FaultType::VMFault as usize;

impl seL4_Fault_t {
    #[inline]
    pub fn get_fault_type(&self) -> FaultType {
        unsafe {
            core::mem::transmute::<u8, FaultType>(((self.words[0] >> 0) & 0xfusize) as u8)
        }
    }

    #[inline]
    pub fn new_null_fault() -> Self {
        Self {
            words: [0 | (seL4_Fault_NullFault & 0xfusize) << 0, 0],
        }
    }

    #[inline]
    pub fn new_cap_fault(address: usize, in_receive_phase: usize) -> Self {
        Self {
            words: [
                0 | (in_receive_phase & 0x1usize) << 63 | (seL4_Fault_CapFault & 0xfusize) << 0,
                0 | address << 0,
            ],
        }
    }

    #[inline]
    pub fn cap_fault_get_address(&self) -> usize {
        self.words[1] & 0xffffffffffffffffusize
    }

    #[inline]
    pub fn cap_fault_get_in_receive_phase(&self) -> usize {
        (self.words[0] & 0x8000000000000000usize) >> 63
    }

    #[inline]
    pub fn new_unknown_syscall_fault(syscall_number: usize) -> Self {
        Self {
            words: [
                0 | (seL4_Fault_UnknownSyscall & 0xfusize) << 0,
                0 | syscall_number << 0,
            ],
        }
    }

    #[inline]
    pub fn unknown_syscall_get_syscall_number(&self) -> usize {
        (self.words[1] & 0xffffffffffffffffusize) >> 0
    }

    #[inline]
    pub fn new_user_exeception(number: usize, code: usize) -> Self {
        Self {
            words: [
                0 | (number & 0xffffffffusize) << 32
                    | (code & 0xfffffffusize) << 4
                    | (seL4_Fault_UserException & 0xfusize) << 0,
                0,
            ],
        }
    }

    #[inline]
    pub fn user_exeception_get_number(&self) -> usize {
        (self.words[0] & 0xffffffff00000000usize) >> 32
    }

    #[inline]
    pub fn user_exeception_get_code(&self) -> usize {
        (self.words[0] & 0xfffffff0usize) >> 4
    }

    #[inline]
    pub fn new_vm_fault(address: usize, fsr: usize, instruction_fault: bool) -> Self {
        Self {
            words: [
                0 | (fsr & 0x1fusize) << 27
                    | (instruction_fault as usize & 0x1usize) << 19
                    | (seL4_Fault_VMFault & 0xfusize) << 0,
                0 | address << 0,
            ],
        }
    }

    #[inline]
    pub fn vm_fault_get_address(&self) -> usize {
        (self.words[1] & 0xffffffffffffffffusize) >> 0
    }

    #[inline]
    pub fn vm_fault_get_fsr(&self) -> usize {
        (self.words[0] & 0xf8000000usize) >> 27
    }

    #[inline]
    pub fn vm_fault_get_instruction_fault(&self) -> usize {
        (self.words[0] & 0x80000usize) >> 19
    }
}

#[inline]
pub fn seL4_Fault_get_seL4_FaultType(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.get_fault_type() as usize
}

#[inline]
pub fn seL4_Fault_NullFault_new() -> seL4_Fault_t {
    seL4_Fault_t::new_null_fault()
}

#[inline]
pub fn seL4_Fault_CapFault_new(address: usize, inReceivePhase: usize) -> seL4_Fault_t {
    seL4_Fault_t::new_cap_fault(address, inReceivePhase)
}

#[inline]
pub fn seL4_Fault_CapFault_get_address(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.cap_fault_get_address()
}

#[inline]
pub fn seL4_Fault_CapFault_get_inReceivePhase(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.cap_fault_get_in_receive_phase()
}

#[inline]
pub fn seL4_Fault_UnknownSyscall_new(syscallNumber: usize) -> seL4_Fault_t {
    seL4_Fault_t::new_unknown_syscall_fault(syscallNumber)
}

#[inline]
pub fn seL4_Fault_UnknownSyscall_get_syscallNumber(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.unknown_syscall_get_syscall_number()
}

#[inline]
pub fn seL4_Fault_UserException_new(number: usize, code: usize) -> seL4_Fault_t {
    seL4_Fault_t::new_user_exeception(number, code)
}

#[inline]
pub fn seL4_Fault_UserException_get_number(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.user_exeception_get_number()
}

#[inline]
pub fn seL4_Fault_UserException_get_code(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.user_exeception_get_code()
}

#[inline]
pub fn seL4_Fault_VMFault_new(address: usize, FSR: usize, instructionFault: bool) -> seL4_Fault_t {
    seL4_Fault_t::new_vm_fault(address, FSR, instructionFault)
}

#[inline]
pub fn seL4_Fault_VMFault_get_address(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.vm_fault_get_address()
}

#[inline]
pub fn seL4_Fault_VMFault_get_FSR(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.vm_fault_get_fsr()
}

#[inline]
pub fn seL4_Fault_VMFault_get_instructionFault(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.vm_fault_get_instruction_fault()
}