use crate::{
    config::seL4_Fault_CapFault,
    object::{
        endpoint::sendIPC,
        structure_gen::{
            seL4_Fault_CapFault_new, seL4_Fault_get_seL4_FaultType,
        },
    },
    structures::{endpoint_t, seL4_Fault_t},
};

use crate::task_manager::*;

use super::{
    boot::{current_fault, current_lookup_fault},
    cspace::lookupCap,
};

use common::structures::{exception_t, lookup_fault_missing_capability_new};
use cspace::interface::*;

#[no_mangle]
pub fn handleFault(tptr: *mut tcb_t) {
    let fault = unsafe { &current_fault };
    let status = sendFaultIPC(tptr);
    if status != exception_t::EXCEPTION_NONE {
        handleDoubleFault(tptr, fault);
    }
}

#[no_mangle]
pub fn sendFaultIPC(tptr: *mut tcb_t) -> exception_t {
    let original_lookup_fault = unsafe { current_lookup_fault };
    let handlerCPtr = unsafe { (*tptr).tcbFaultHandler };
    let lu_ret = lookupCap(tptr, handlerCPtr);
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_fault = seL4_Fault_CapFault_new(handlerCPtr, 0);
            return exception_t::EXCEPTION_FAULT;
        }
    }
    let handlerCap = &lu_ret.cap;
    if cap_get_capType(handlerCap) == cap_endpoint_cap
        && cap_endpoint_cap_get_capCanSend(handlerCap) != 0
        && (cap_endpoint_cap_get_capCanGrant(handlerCap) != 0
            || cap_endpoint_cap_get_capCanGrantReply(handlerCap) != 0)
    {
        unsafe {
            (*tptr).tcbFault = current_fault;
            if seL4_Fault_get_seL4_FaultType(&current_fault) == seL4_Fault_CapFault {
                (*tptr).tcbLookupFailure = original_lookup_fault;
            }
            sendIPC(
                true,
                true,
                cap_endpoint_cap_get_capEPBadge(handlerCap),
                cap_endpoint_cap_get_capCanGrant(handlerCap) != 0,
                true,
                tptr,
                cap_endpoint_cap_get_capEPPtr(handlerCap) as *mut endpoint_t,
            );
            return exception_t::EXCEPTION_NONE;
        }
    } else {
        unsafe {
            current_fault = seL4_Fault_CapFault_new(handlerCPtr, 0);
            current_lookup_fault = lookup_fault_missing_capability_new(0);
            return exception_t::EXCEPTION_FAULT;
        }
    }
}

#[no_mangle]
pub fn handleDoubleFault(tptr: *mut tcb_t, _ex1: &seL4_Fault_t) {
    setThreadState(tptr, ThreadStateInactive);
}
