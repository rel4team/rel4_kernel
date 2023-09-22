

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
