use core::f64::MIN;

use crate::{
    config::{
        lookup_fault_depth_mismatch, lookup_fault_guard_mismatch, lookup_fault_invalid_root,
        lookup_fault_missing_capability, msgRegister, n_msgRegisters, seL4_CapFault_Addr,
        seL4_CapFault_BitsLeft, seL4_CapFault_DepthMismatch_BitsFound,
        seL4_CapFault_GuardMismatch_BitsFound, seL4_CapFault_GuardMismatch_GuardFound,
        seL4_CapFault_IP, seL4_CapFault_InRecvPhase, seL4_CapFault_LookupFailureType,
        seL4_Fault_CapFault, seL4_Fault_UnknownSyscall, MAX_MSG_SIZE,
    },
    object::structure_gen::{
        lookup_fault_depth_mismatch_get_bitsFound, lookup_fault_depth_mismatch_get_bitsLeft,
        lookup_fault_get_lufType, lookup_fault_guard_mismatch_get_bitsFound,
        lookup_fault_guard_mismatch_get_bitsLeft, lookup_fault_guard_mismatch_get_guardFound,
        lookup_fault_missing_capability_get_bitsLeft, seL4_Fault_CapFault_get_address,
        seL4_Fault_CapFault_get_inReceivePhase, seL4_Fault_get_seL4_FaultType,
    },
    structures::{lookup_fault_t, tcb_t},
};

pub const fault_messages: [[usize; MAX_MSG_SIZE]; 2] = [
    [33, 1, 0, 9, 10, 11, 12, 13, 14, 15],
    [33, 1, 0, 0, 0, 0, 0, 0, 0, 0],
];

use super::{
    thread::{getReStartPC, getRegister, setMR, setRegister},
    vspace::lookupIPCBuffer,
};

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
            }
        }
    }
}

// pub fn setMRs_fault(
//     sender: *mut tcb_t,
//     receiver: *mut tcb_t,
//     receiveIPCBuffer: *mut usize,
// ) -> usize {
//     unsafe {
//         match seL4_Fault_get_seL4_FaultType(&(*sender).tcbFault) {
//             seL4_Fault_CapFault => {
//                 setMR(
//                     receiver,
//                     receiveIPCBuffer,
//                     seL4_CapFault_IP,
//                     getReStartPC(sender),
//                 );
//                 setMR(
//                     receiver,
//                     receiveIPCBuffer,
//                     seL4_CapFault_Addr,
//                     seL4_Fault_CapFault_get_address(&(*sender).tcbFault),
//                 );
//                 setMR(
//                     receiver,
//                     receiveIPCBuffer,
//                     seL4_CapFault_InRecvPhase,
//                     seL4_Fault_CapFault_get_inReceivePhase(&(*sender).tcbFault),
//                 );
//                 setMRs_lookup_failure(
//                     receiver,
//                     receiveIPCBuffer,
//                     &(*sender).tcbLookupFailure,
//                     seL4_CapFault_LookupFailureType,
//                 )
//             }
//             seL4_Fault_UnknownSyscall => {}
//         }
//     }
// }

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
