use common::{sel4_config::{MessageID_Syscall, MessageID_Exception}, fault::{seL4_CapFault_IP, seL4_CapFault_Addr, seL4_CapFault_InRecvPhase, seL4_CapFault_LookupFailureType, seL4_CapFault_BitsLeft, seL4_CapFault_DepthMismatch_BitsFound, seL4_CapFault_GuardMismatch_GuardFound, seL4_CapFault_GuardMismatch_BitsFound}, structures::seL4_IPCBuffer};

use crate::{tcb_t, n_msgRegisters, msgRegister, fault_messages, n_syscallMessage, n_exceptionMessage, FaultIP};

impl tcb_t {
    #[inline]
    pub fn copy_fault_mrs(&self, receiver: &mut Self, id: usize, length: usize) {
        let len = if length < n_msgRegisters {
            length
        } else {
            n_msgRegisters
        };
        let mut i = 0;
        while i < len {
            receiver.set_register(msgRegister[i], self.get_register(fault_messages[id][i]));
            i += 1;
        }
        if let Some(buffer) = receiver.lookup_mut_ipc_buffer(true) {
            while i < length {
                buffer.msg[i] = self.get_register(fault_messages[id][i]);
                i += 1;
            }
        }
    }

    #[inline]
    pub fn copy_syscall_fault_mrs(&self, receiver: &mut Self) {
        self.copy_fault_mrs(receiver, MessageID_Syscall, n_syscallMessage)
    }
    
    #[inline]
    pub fn copy_exeception_fault_mrs(&self, receiver: &mut Self) {
        self.copy_fault_mrs(receiver, MessageID_Exception, n_exceptionMessage)
    }

    #[inline]
    fn set_lookup_fault_mrs(&self, receiver: &mut Self, offset: usize) -> usize {
        let fault = self.tcbLookupFailure;
        let luf_type = fault.get_type();
        let i = receiver.set_mr(offset, luf_type + 1);
        if offset == seL4_CapFault_LookupFailureType {
            assert_eq!(offset + 1, seL4_CapFault_BitsLeft);
            assert_eq!(offset + 2, seL4_CapFault_DepthMismatch_BitsFound);
            assert_eq!(offset + 3, seL4_CapFault_GuardMismatch_GuardFound);
            assert_eq!(offset + 4, seL4_CapFault_GuardMismatch_BitsFound);
        } else {
            assert_eq!(offset, 1);
        }
        match fault.get_lookup_fault_type() {
            common::fault::LookupFaultType::InvaildRoot => i,
            common::fault::LookupFaultType::MissingCap => {
                receiver.set_mr(offset + 1, fault.missing_cap_get_bits_left())
            },
            common::fault::LookupFaultType::DepthMismatch => {
                receiver.set_mr(offset + 1, fault.depth_mismatch_get_bits_left());
                receiver.set_mr(offset + 2, fault.depth_mismatch_get_bits_found())
            },
            common::fault::LookupFaultType::GuardMismatch => {
                receiver.set_mr(offset + 1, fault.guard_mismatch_get_bits_left());
                receiver.set_mr(offset + 2, fault.guard_mismatch_get_guard_found());
                receiver.set_mr(offset + 3, fault.guard_mismatch_get_bits_found())
            }
        }
    }

    #[inline]
    pub fn set_fault_mrs(&self, receiver: &mut Self) {
        match self.tcbFault.get_fault_type() {
            common::fault::FaultType::CapFault => {
                receiver.set_mr(seL4_CapFault_IP, self.get_register(FaultIP));
                receiver.set_mr(seL4_CapFault_Addr, self.tcbFault.cap_fault_get_address());
                receiver.set_mr(seL4_CapFault_InRecvPhase, self.tcbFault.cap_fault_get_in_receive_phase());
            },
            common::fault::FaultType::UnknownSyscall => todo!(),
            common::fault::FaultType::UserException => todo!(),
            common::fault::FaultType::VMFault => todo!(),
            _ => {
                
            }
        }
        // match seL4_Fault_get_seL4_FaultType(&(*sender).tcbFault) {
        //     seL4_Fault_CapFault => {
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             seL4_CapFault_IP,
        //             getReStartPC(sender),
        //         );
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             seL4_CapFault_Addr,
        //             seL4_Fault_CapFault_get_address(&(*sender).tcbFault),
        //         );
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             seL4_CapFault_InRecvPhase,
        //             seL4_Fault_CapFault_get_inReceivePhase(&(*sender).tcbFault),
        //         );
        //         setMRs_lookup_failure(
        //             receiver,
        //             receiveIPCBuffer,
        //             &(*sender).tcbLookupFailure,
        //             seL4_CapFault_LookupFailureType,
        //         )
        //     }
        //     seL4_Fault_UnknownSyscall => {
        //         copyMRsFault(
        //             sender,
        //             receiver,
        //             MessageID_Syscall,
        //             n_syscallMessage,
        //             receiveIPCBuffer,
        //         );
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             n_syscallMessage,
        //             seL4_Fault_UnknownSyscall_get_syscallNumber(&(*sender).tcbFault),
        //         )
        //     }
        //     seL4_Fault_UserException => {
        //         copyMRsFault(
        //             sender,
        //             receiver,
        //             MessageID_Exception,
        //             n_exceptionMessage,
        //             receiveIPCBuffer,
        //         );
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             n_exceptionMessage,
        //             seL4_Fault_UserException_get_number(&(*sender).tcbFault),
        //         );
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             n_exceptionMessage + 1,
        //             seL4_Fault_UserException_get_code(&(*sender).tcbFault),
        //         )
        //     }
        //     seL4_Fault_VMFault => {
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             seL4_VMFault_IP,
        //             getReStartPC(sender),
        //         );
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             seL4_VMFault_Addr,
        //             seL4_Fault_VMFault_get_address(&(*sender).tcbFault),
        //         );
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             seL4_VMFault_PrefetchFault,
        //             seL4_Fault_VMFault_get_instructionFault(&(*sender).tcbFault),
        //         );
        //         setMR(
        //             receiver,
        //             receiveIPCBuffer,
        //             seL4_VMFault_FSR,
        //             seL4_Fault_VMFault_get_FSR(&(*sender).tcbFault),
        //         )
        //     }
        //     _ => panic!("invalid fault"),
        // }
    }
}


#[no_mangle]
pub fn copyMRsFault(
    sender: *mut tcb_t,
    receiver: *mut tcb_t,
    id: usize,
    length: usize,
    _receiveIPCBuffer: *mut usize,
) {
    unsafe {
        (*sender).copy_fault_mrs(&mut *receiver, id, length)
    }
}
