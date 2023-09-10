#![feature(core_intrinsics)]
#![no_std]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

mod notification;
mod endpoint;

use common::{utils::convert_to_mut_type_ref, structures::seL4_Fault_NullFault_new, sel4_config::tcbReply};
use cspace::interface::cte_t;
pub use endpoint::*;
pub use notification::*;
use task_manager::{tcb_t, ThreadState};

pub fn cancel_ipc(tcb: &mut tcb_t) {
    let state = tcb.tcbState;
    match tcb.get_state() {
        ThreadState::ThreadStateBlockedOnSend | ThreadState::ThreadStateBlockedOnReceive => {
            let ep = convert_to_mut_type_ref::<endpoint_t>(state.get_blocking_object());
            assert_ne!(ep.get_state(), EPState::Idle);
            ep.cancel_ipc(tcb);
        }
        ThreadState::ThreadStateBlockedOnNotification => {
            let ntfn = convert_to_mut_type_ref::<notification_t>(state.get_blocking_object());
            ntfn.cancel_signal(tcb);
        }

        ThreadState::ThreadStateBlockedOnReply => {
            tcb.tcbFault = seL4_Fault_NullFault_new();
            let slot = tcb.get_cspace(tcbReply);
            let caller_slot_ptr = slot.cteMDBNode.get_next();
            if caller_slot_ptr != 0 {
                convert_to_mut_type_ref::<cte_t>(caller_slot_ptr).delete_one()
            }
        }
        _ => {}
    }
    
}

#[no_mangle]
pub fn cancelIPC(tptr: *mut tcb_t) {
    unsafe {
        cancel_ipc(&mut *tptr);
    }
}