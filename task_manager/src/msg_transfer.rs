use common::{sel4_config::{MessageID_Syscall, MessageID_Exception}, fault::{seL4_CapFault_IP, seL4_CapFault_Addr, seL4_CapFault_InRecvPhase, seL4_CapFault_LookupFailureType, seL4_VMFault_IP, seL4_VMFault_Addr, seL4_VMFault_PrefetchFault, seL4_VMFault_FSR}};

use crate::{tcb_t, n_msgRegisters, msgRegister, fault_messages, n_syscallMessage, n_exceptionMessage, FaultIP};



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


#[no_mangle]
pub fn setMRs_fault(
    sender: *mut tcb_t,
    receiver: *mut tcb_t,
    _receiveIPCBuffer: *mut usize,
) -> usize {
    unsafe {
        (*sender).set_fault_mrs(&mut *receiver)
    }
}