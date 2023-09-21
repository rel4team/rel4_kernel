
use crate::config::{
    seL4_VMFault_Addr, seL4_VMFault_FSR,
    seL4_VMFault_IP, seL4_VMFault_PrefetchFault,
};

use task_manager::*;

use common::{sel4_config::*, message_info::*, fault::*};


use super::thread::setMR;

#[no_mangle]
pub fn copyMRsFaultReply(sender: *mut tcb_t, receiver: *mut tcb_t, id: usize, length: usize) {
    let mut i = 0;
    let len = if length < n_msgRegisters {
        length
    } else {
        n_msgRegisters
    };
    while i < len {
        let r = fault_messages[id][i];
        let v = getRegister(sender, msgRegister[i]);
        setRegister(receiver, r, v);
        i += 1;
    }
    if i < length {
        let sendBuf = lookupIPCBuffer(false, sender) as *mut usize;

        if sendBuf as usize != 0 {
            while i < length {
                let r = fault_messages[id][i];
                let v = unsafe { *sendBuf.add(i + 1) };
                setRegister(receiver, r, v);
                i += 1;
            }
        }
    }
}

#[no_mangle]
pub fn process3(sender: *mut tcb_t, receiver: *mut tcb_t, receiveIPCBuffer: *mut usize) -> usize {
    unsafe {
        copyMRsFault(
            sender,
            receiver,
            MessageID_Syscall,
            n_syscallMessage,
            receiveIPCBuffer,
        );
        setMR(
            receiver,
            receiveIPCBuffer,
            n_syscallMessage,
            seL4_Fault_UnknownSyscall_get_syscallNumber(&(*sender).tcbFault),
        )
    }
}

#[no_mangle]
pub fn setMRs_fault(
    sender: *mut tcb_t,
    receiver: *mut tcb_t,
    receiveIPCBuffer: *mut usize,
) -> usize {
    unsafe {
        match seL4_Fault_get_seL4_FaultType(&(*sender).tcbFault) {
            seL4_Fault_CapFault => {
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    seL4_CapFault_IP,
                    getReStartPC(sender),
                );
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    seL4_CapFault_Addr,
                    seL4_Fault_CapFault_get_address(&(*sender).tcbFault),
                );
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    seL4_CapFault_InRecvPhase,
                    seL4_Fault_CapFault_get_inReceivePhase(&(*sender).tcbFault),
                );
                setMRs_lookup_failure(
                    receiver,
                    receiveIPCBuffer,
                    &(*sender).tcbLookupFailure,
                    seL4_CapFault_LookupFailureType,
                )
            }
            seL4_Fault_UnknownSyscall => {
                copyMRsFault(
                    sender,
                    receiver,
                    MessageID_Syscall,
                    n_syscallMessage,
                    receiveIPCBuffer,
                );
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    n_syscallMessage,
                    seL4_Fault_UnknownSyscall_get_syscallNumber(&(*sender).tcbFault),
                )
            }
            seL4_Fault_UserException => {
                copyMRsFault(
                    sender,
                    receiver,
                    MessageID_Exception,
                    n_exceptionMessage,
                    receiveIPCBuffer,
                );
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    n_exceptionMessage,
                    seL4_Fault_UserException_get_number(&(*sender).tcbFault),
                );
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    n_exceptionMessage + 1,
                    seL4_Fault_UserException_get_code(&(*sender).tcbFault),
                )
            }
            seL4_Fault_VMFault => {
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    seL4_VMFault_IP,
                    getReStartPC(sender),
                );
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    seL4_VMFault_Addr,
                    seL4_Fault_VMFault_get_address(&(*sender).tcbFault),
                );
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    seL4_VMFault_PrefetchFault,
                    seL4_Fault_VMFault_get_instructionFault(&(*sender).tcbFault),
                );
                setMR(
                    receiver,
                    receiveIPCBuffer,
                    seL4_VMFault_FSR,
                    seL4_Fault_VMFault_get_FSR(&(*sender).tcbFault),
                )
            }
            _ => panic!("invalid fault"),
        }
    }
}

pub fn setMRs_lookup_failure(
    receiver: *mut tcb_t,
    receiveIPCBuffer: *mut usize,
    luf: &lookup_fault_t,
    offset: usize,
) -> usize {
    let lufType = lookup_fault_get_lufType(luf);
    let i = setMR(receiver, receiveIPCBuffer, offset, lufType + 1);

    if offset == seL4_CapFault_LookupFailureType {
        assert!(offset + 1 == seL4_CapFault_BitsLeft);
        assert!(offset + 2 == seL4_CapFault_DepthMismatch_BitsFound);
        assert!(offset + 2 == seL4_CapFault_GuardMismatch_GuardFound);
        assert!(offset + 3 == seL4_CapFault_GuardMismatch_BitsFound);
    } else {
        assert!(offset == 1);
    }

    match lufType {
        lookup_fault_invalid_root => i,
        lookup_fault_missing_capability => setMR(
            receiver,
            receiveIPCBuffer,
            offset + 1,
            lookup_fault_missing_capability_get_bitsLeft(luf),
        ),
        lookup_fault_depth_mismatch => {
            setMR(
                receiver,
                receiveIPCBuffer,
                offset + 1,
                lookup_fault_depth_mismatch_get_bitsLeft(luf),
            );
            setMR(
                receiver,
                receiveIPCBuffer,
                offset + 2,
                lookup_fault_depth_mismatch_get_bitsFound(luf),
            )
        }
        lookup_fault_guard_mismatch => {
            setMR(
                receiver,
                receiveIPCBuffer,
                offset + 1,
                lookup_fault_guard_mismatch_get_bitsLeft(luf),
            );
            setMR(
                receiver,
                receiveIPCBuffer,
                offset + 2,
                lookup_fault_guard_mismatch_get_guardFound(luf),
            );
            setMR(
                receiver,
                receiveIPCBuffer,
                offset + 3,
                lookup_fault_guard_mismatch_get_bitsFound(luf),
            )
        }
        _ => panic!("invalid lookup failure"),
    }
}

#[no_mangle]
pub fn handleFaultReply(receiver: *mut tcb_t, sender: *mut tcb_t) -> bool {
    let tag = messageInfoFromWord(getRegister(sender, msgInfoRegister));
    let label = seL4_MessageInfo_ptr_get_label(&tag as *const seL4_MessageInfo_t);
    let length = seL4_MessageInfo_ptr_get_length(&tag as *const seL4_MessageInfo_t);
    let fault = unsafe { &(*receiver).tcbFault };
    match seL4_Fault_get_seL4_FaultType(&fault) {
        seL4_Fault_CapFault => true,
        seL4_Fault_UnknownSyscall => {
            copyMRsFaultReply(
                sender,
                receiver,
                MessageID_Syscall,
                core::cmp::min(length, n_syscallMessage),
            );
            return label == 0;
        }
        seL4_Fault_UserException => {
            copyMRsFaultReply(
                sender,
                receiver,
                MessageID_Exception,
                core::cmp::min(length, n_exceptionMessage),
            );
            return label == 0;
        }
        seL4_Fault_VMFault => true,
        _ => panic!("Invalid fault"),
    }
}
