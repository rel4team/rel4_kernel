use crate::structures::*;

use super::super::notification::notification_t;
use super::register::n_contextRegisters;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct tcb_t {
    pub tcbArch: arch_tcb_t,
    pub tcbState: thread_state_t,
    pub tcbBoundNotification: *mut notification_t,
    pub tcbFault: seL4_Fault_t,
    pub tcbLookupFailure: lookup_fault_t,
    pub domain: usize,
    pub tcbMCP: usize,
    pub tcbPriority: usize,
    pub tcbTimeSlice: usize,
    pub tcbFaultHandler: usize,
    pub tcbIPCBuffer: usize,
    pub tcbSchedNext: usize,
    pub tcbSchedPrev: usize,
    pub tcbEPNext: usize,
    pub tcbEPPrev: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct tcb_queue_t {
    pub head: *mut tcb_t,
    pub tail: *mut tcb_t,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct arch_tcb_t {
    pub registers: [usize; n_contextRegisters],
}

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct thread_state_t {
    pub words: [usize; 3],
}
