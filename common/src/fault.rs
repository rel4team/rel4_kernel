
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

pub const seL4_CapFault_IP: usize = 0;
pub const seL4_CapFault_Addr: usize = 1;
pub const seL4_CapFault_InRecvPhase: usize = 2;
pub const seL4_CapFault_LookupFailureType: usize = 3;
pub const seL4_CapFault_BitsLeft: usize = 4;
pub const seL4_CapFault_DepthMismatch_BitsFound: usize = 5;
pub const seL4_CapFault_GuardMismatch_GuardFound: usize = seL4_CapFault_DepthMismatch_BitsFound;
pub const seL4_CapFault_GuardMismatch_BitsFound: usize = 6;

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


// lookup_fault
pub const lookup_fault_invalid_root: usize = 0;
pub const lookup_fault_missing_capability: usize = 1;
pub const lookup_fault_depth_mismatch: usize = 2;
pub const lookup_fault_guard_mismatch: usize = 3;



#[derive(PartialEq, Eq)]
pub enum LookupFaultType {
    InvaildRoot = 0,
    MissingCap = 1,
    DepthMismatch = 2,
    GuardMismatch = 3,
}

#[macro_export]
macro_rules! define_bitfield {
    ($name:ident, $type_offset:expr, $type_bits:expr =>
        { $($variant:ident, $type_value:expr => { $($field:ident, $get_field:ident, $set_field:ident, $offset:expr, $bits:expr, $addr:expr),* }),* }) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub struct $name(pub u128);

        impl $name {
            $(
                #[inline]
                pub fn $variant($($field: usize),*) -> Self {
                    let mut value: u128 = 0;
                    $(
                        let mask = (1 << $bits) - 1;
                        value |= (($field as u128) & mask) << $offset;
                    )*
                    let mask = (1 << $type_bits) - 1;
                    value |= (($type_value as u128) & mask) << $type_offset;

                    $name(value)
                }

                $(
                    #[inline]
                    pub fn $get_field(&self) -> usize {
                        let mask = (1 << $bits) - 1;
                        let value = ((self.0 >> $offset) & mask) as usize;
                        if $addr {
                            // 符号扩展
                            if value >> ($bits - 1) == 1 {
                                value | (!mask as usize)
                            } else {
                                value
                            }
                        } else {
                            value
                        }
                    }
                    #[inline]
                    pub fn $set_field(&mut self, new_field: usize) {
                        let mask = (1 << $bits) - 1;
                        self.0 &= !(mask << $offset);

                        self.0 |= (((new_field as u128) & mask) << $offset);
                    }
                )*
            )*
            
            #[inline]
            pub fn get_type(&self) -> usize {
                let mask = (1 << $type_bits) - 1;
                let value = ((self.0 >> $type_offset) & mask) as usize;
                value
            }
        }
    };
}

define_bitfield! {
    lookup_fault_t, 0, 2 => {
        new_root_invalid, lookup_fault_invalid_root => {},
        new_missing_cap, lookup_fault_missing_capability => {
            bits_left, missing_cap_get_bits_left, missing_cap_set_bits_left, 2, 7, false
        },
        new_depth_mismatch, lookup_fault_depth_mismatch => {
            bits_found, depth_mismatch_get_bits_found, depth_mismatch_set_bits_found, 9, 7, false, 
            bits_left, depth_mismatch_get_bits_left,  depth_mismatch_set_bits_left, 2, 7, false
        },
        new_guard_mismatch, lookup_fault_depth_mismatch => {
            guard_found, guard_mismatch_get_guard_found, guard_mismatch_set_guard_found, 64, 64, false,
            bits_found, guard_mismatch_get_bits_found, guard_mismatch_set_bits_found, 9, 7, false, 
            bits_left, guard_mismatch_get_bits_left,  guard_mismatch_set_bits_left, 2, 7, false
        }
    }
}


// #[repr(C)]
// #[derive(Debug, PartialEq, Clone, Copy)]
// pub struct lookup_fault_t {
//     pub words: [usize; 2],
// }

// impl lookup_fault_t {
//     #[inline]
//     pub fn get_fault_type(&self) -> LookupFaultType {
//         unsafe {
//             core::mem::transmute::<u8, LookupFaultType>(((self.words[0] >> 0) & 0x3usize) as u8)
//         }
//     }

//     #[inline]
//     pub fn new_root_invalid() -> Self {
//         Self {
//             words: [0 | (lookup_fault_invalid_root & 0x3usize) << 0, 0],
//         }
//     }

//     #[inline]
//     pub fn new_missing_cap(bits_left: usize) -> Self {
//         Self {
//             words: [
//                 0 | (bits_left & 0x7fusize) << 2 | (lookup_fault_missing_capability & 0x3usize) << 0,
//                 0,
//             ],
//         }
//     }

//     #[inline]
//     pub fn missing_cap_get_bits_left(&self) -> usize {
//         (self.words[0] & 0x1fcusize) >> 2
//     }

//     #[inline]
//     pub fn new_depth_mismatch(bits_found: usize, bits_left: usize) -> Self {
//         Self {
//             words: [
//                 0 | (bits_found & 0x7fusize) << 9
//                     | (bits_left & 0x7fusize) << 2
//                     | (lookup_fault_depth_mismatch & 0x3usize) << 0,
//                 0,
//             ],
//         }
//     }

//     #[inline]
//     pub fn depth_mismatch_get_bits_found(&self) -> usize {
//         (self.words[0] & 0xfe00usize) >> 9
//     }

//     #[inline]
//     pub fn depth_mismatch_get_bits_left(&self) -> usize {
//         (self.words[0] & 0x1fcusize) >> 2
//     }

//     #[inline]
//     pub fn new_guard_mismatch(guard_found: usize, bits_found: usize, bits_left: usize) -> Self {
//         Self {
//             words: [
//                 0 | (bits_found & 0x7fusize) << 9
//                     | (bits_left & 0x7fusize) << 2
//                     | (lookup_fault_depth_mismatch & 0x3usize) << 0,
//                 0 | guard_found << 0,
//             ],
//         }
//     }

//     #[inline]
//     pub fn guard_mismatch_get_guard_found(&self) -> usize {
//         (self.words[1] & 0xffffffffffffffffusize) >> 0
//     }

//     #[inline]
//     pub fn guard_mismatch_get_bits_found(&self) -> usize {
//         (self.words[0] & 0xfe00usize) >> 9
//     }

//     #[inline]
//     pub fn guard_mismatch_get_bits_left(&self) -> usize {
//         (self.words[0] & 0x1fcusize) >> 2
//     }
// }

#[inline]
pub fn lookup_fault_get_lufType(lookup_fault: &lookup_fault_t) -> usize {
    lookup_fault.get_type() as usize
}

#[inline]
pub fn lookup_fault_invalid_root_new() -> lookup_fault_t {
    lookup_fault_t::new_root_invalid()
}

#[inline]
pub fn lookup_fault_missing_capability_new(bitsLeft: usize) -> lookup_fault_t {
    lookup_fault_t::new_missing_cap(bitsLeft)
}

#[inline]
pub fn lookup_fault_missing_capability_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    lookup_fault.missing_cap_get_bits_left()
}

#[inline]
pub fn lookup_fault_depth_mismatch_new(bitsFound: usize, bitsLeft: usize) -> lookup_fault_t {
    lookup_fault_t::new_depth_mismatch(bitsFound, bitsLeft)
}

#[inline]
pub fn lookup_fault_depth_mismatch_get_bitsFound(lookup_fault: &lookup_fault_t) -> usize {
    lookup_fault.depth_mismatch_get_bits_found()
}

#[inline]
pub fn lookup_fault_depth_mismatch_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    lookup_fault.depth_mismatch_get_bits_left()
}

#[inline]
pub fn lookup_fault_guard_mismatch_new(
    guardFound: usize,
    bitsFound: usize,
    bitsLeft: usize,
) -> lookup_fault_t {
    lookup_fault_t::new_guard_mismatch(guardFound, bitsFound, bitsLeft)
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_guardFound(lookup_fault: &lookup_fault_t) -> usize {
    lookup_fault.guard_mismatch_get_guard_found()
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_bitsFound(lookup_fault: &lookup_fault_t) -> usize {
    lookup_fault.guard_mismatch_get_bits_found()
}

#[inline]
pub fn lookup_fault_guard_mismatch_get_bitsLeft(lookup_fault: &lookup_fault_t) -> usize {
    lookup_fault.guard_mismatch_get_bits_left()
}