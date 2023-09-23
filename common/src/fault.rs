use crate::plus_define_bitfield;

plus_define_bitfield! {
    seL4_Fault_t, 2, 0, 0, 4 => {
        new_null_fault, seL4_Fault_NullFault => {},
        new_cap_fault, seL4_Fault_CapFault => {
            address, cap_fault_get_address, cap_fault_set_address, 1, 0, 64, 0, false,
            in_receive_phase, cap_fault_get_in_receive_phase, cap_fault_set_in_receive_phase, 0, 63, 1, 0, false
        },
        new_unknown_syscall_fault, seL4_Fault_UnknownSyscall => {
            syscall_number, unknown_syscall_get_syscall_number, unknown_syscall_set_syscall_number, 1, 0, 64, 0, false
        },
        new_user_exeception, seL4_Fault_UserException => {
            number, user_exeception_get_number, user_exeception_set_number, 0, 32, 32, 0, false,
            code, user_exeception_get_code, user_exeception_set_code, 0, 4, 28, 0, false
        },
        new_vm_fault, seL4_Fault_VMFault => {
            address, vm_fault_get_address, vm_fault_set_address, 1, 0, 64, 0, false,
            fsr, vm_fault_get_fsr, vm_fault_set_fsr, 0, 27, 5, 0, false,
            instruction_fault, vm_fault_get_instruction_fault, vm_fault_set_instruction_fault, 0, 19, 1, 0, false
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultType {
    NullFault = 0,
    CapFault = 1,
    UnknownSyscall = 2,
    UserException = 3,
    VMFault = 5,
}

impl seL4_Fault_t {
    pub fn get_fault_type(&self) -> FaultType {
        unsafe {
            core::mem::transmute::<u8, FaultType>(self.get_type() as u8)
        }
    }
}


pub const seL4_Fault_NullFault: usize = FaultType::NullFault as usize;
pub const seL4_Fault_CapFault: usize = FaultType::CapFault as usize;
pub const seL4_Fault_UnknownSyscall: usize = FaultType::UnknownSyscall as usize;
pub const seL4_Fault_UserException: usize = FaultType::UserException as usize;
pub const seL4_Fault_VMFault: usize = FaultType::VMFault as usize;

//seL4_VMFault_Msg
pub const seL4_VMFault_IP: usize = 0;
pub const seL4_VMFault_Addr: usize = 1;
pub const seL4_VMFault_PrefetchFault: usize = 2;
pub const seL4_VMFault_FSR: usize = 3;
pub const seL4_VMFault_Length: usize = 4;

pub const seL4_CapFault_IP: usize = 0;
pub const seL4_CapFault_Addr: usize = 1;
pub const seL4_CapFault_InRecvPhase: usize = 2;
pub const seL4_CapFault_LookupFailureType: usize = 3;
pub const seL4_CapFault_BitsLeft: usize = 4;
pub const seL4_CapFault_DepthMismatch_BitsFound: usize = 5;
pub const seL4_CapFault_GuardMismatch_GuardFound: usize = seL4_CapFault_DepthMismatch_BitsFound;
pub const seL4_CapFault_GuardMismatch_BitsFound: usize = 6;


#[inline]
pub fn seL4_Fault_get_seL4_FaultType(seL4_Fault: &seL4_Fault_t) -> usize {
    seL4_Fault.get_type() as usize
}


#[inline]
pub fn seL4_Fault_CapFault_new(address: usize, inReceivePhase: usize) -> seL4_Fault_t {
    seL4_Fault_t::new_cap_fault(address, inReceivePhase)
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
pub fn seL4_Fault_VMFault_new(address: usize, FSR: usize, instructionFault: bool) -> seL4_Fault_t {
    seL4_Fault_t::new_vm_fault(address, FSR, instructionFault as usize)
}


// lookup_fault
#[derive(PartialEq, Eq)]
pub enum LookupFaultType {
    InvaildRoot = 0,
    MissingCap = 1,
    DepthMismatch = 2,
    GuardMismatch = 3,
}

pub const lookup_fault_invalid_root: usize = LookupFaultType::InvaildRoot as usize;
pub const lookup_fault_missing_capability: usize = LookupFaultType::MissingCap as usize;
pub const lookup_fault_depth_mismatch: usize = LookupFaultType::DepthMismatch as usize;
pub const lookup_fault_guard_mismatch: usize = LookupFaultType::GuardMismatch as usize;


plus_define_bitfield! {
    lookup_fault_t, 2, 0, 0, 2 => {
        new_root_invalid, lookup_fault_invalid_root => {},
        new_missing_cap, lookup_fault_missing_capability => {
            bits_left, missing_cap_get_bits_left, missing_cap_set_bits_left, 0, 2, 7, 0, false
        },
        new_depth_mismatch, lookup_fault_depth_mismatch => {
            bits_found, depth_mismatch_get_bits_found, depth_mismatch_set_bits_found, 0, 9, 7, 0, false,
            bits_left, depth_mismatch_get_bits_left,  depth_mismatch_set_bits_left, 0, 2, 7, 0, false
        },
        new_guard_mismatch, lookup_fault_depth_mismatch => {
            guard_found, guard_mismatch_get_guard_found, guard_mismatch_set_guard_found, 1, 0, 64, 0, false,
            bits_found, guard_mismatch_get_bits_found, guard_mismatch_set_bits_found, 0, 9, 7, 0, false,
            bits_left, guard_mismatch_get_bits_left,  guard_mismatch_set_bits_left, 0, 2, 7, 0, false
        }
    }
}

impl lookup_fault_t {
    pub fn get_lookup_fault_type(&self) -> LookupFaultType {
        unsafe {
            core::mem::transmute::<u8, LookupFaultType>(self.get_type() as u8)
        }
    }
}


#[inline]
pub fn lookup_fault_missing_capability_new(bitsLeft: usize) -> lookup_fault_t {
    lookup_fault_t::new_missing_cap(bitsLeft)
}
