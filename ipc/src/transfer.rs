use task_manager::tcb_t;

pub fn do_fault_transfer(badge: usize, sender: &mut tcb_t, receiver: &mut tcb_t) {

}

// #[no_mangle]
// pub fn doFaultTransfer(
//     badge: usize,
//     sender: *mut tcb_t,
//     receiver: *mut tcb_t,
//     receivedIPCBuffer: *mut usize,
// ) {
//     // let sent = setMRs_fault(sender, receiver, receivedIPCBuffer);
//     // let msgInfo = unsafe {
//     //     seL4_MessageInfo_new(
//     //         seL4_Fault_get_seL4_FaultType(&(*sender).tcbFault),
//     //         0,
//     //         0,
//     //         sent,
//     //     )
//     // };
//     // setRegister(receiver, msgInfoRegister, wordFromMessageInfo(msgInfo));
//     // setRegister(receiver, badgeRegister, badge);
// }
