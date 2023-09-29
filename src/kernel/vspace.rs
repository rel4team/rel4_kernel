use common::fault::seL4_Fault_VMFault_new;
use common::message_info::*;
use common::{structures::exception_t, sel4_config::*};
use vspace::*;
use crate::{
    config::{
        RISCVInstructionAccessFault, RISCVInstructionPageFault, RISCVLoadAccessFault,
        RISCVStoreAccessFault, RISCVStorePageFault, RISCVLoadPageFault
    },
    riscv::read_stval,

};
use task_manager::*;

use super:: boot::{
    current_fault, current_lookup_fault,
};

use cspace::interface::*;

#[no_mangle]
pub fn handleVMFault(_thread: *mut tcb_t, _type: usize) -> exception_t {
    let addr = read_stval();
    match _type {
        RISCVLoadPageFault | RISCVLoadAccessFault => {
            unsafe {
                current_fault = seL4_Fault_VMFault_new(addr, RISCVLoadAccessFault, false);
            }
            exception_t::EXCEPTION_FAULT
        }
        RISCVStorePageFault | RISCVStoreAccessFault => {
            unsafe {
                current_fault = seL4_Fault_VMFault_new(addr, RISCVStoreAccessFault, false);
            }
            exception_t::EXCEPTION_FAULT
        }
        RISCVInstructionAccessFault | RISCVInstructionPageFault => {
            unsafe {
                current_fault = seL4_Fault_VMFault_new(addr, RISCVInstructionAccessFault, true);
            }
            exception_t::EXCEPTION_FAULT
        }
        _ => panic!("Invalid VM fault type:{}", _type),
    }
}

#[no_mangle]
pub fn deleteASIDPool(asid_base: asid_t, pool: *mut asid_pool_t) {
    unsafe {
        if let Err(lookup_fault) = delete_asid_pool(asid_base, pool, &(*getCSpace(ksCurThread as usize, tcbVTable)).cap) {
            current_lookup_fault = lookup_fault;
        }
    }
}

#[no_mangle]
pub fn deleteASID(asid: asid_t, vspace: *mut pte_t) {
    unsafe {
        if let Err(lookup_fault) = delete_asid(asid, vspace, &(*getCSpace(ksCurThread as usize, tcbVTable)).cap) {
            current_lookup_fault = lookup_fault;
        }
    }
}

#[no_mangle]
pub fn decodeRISCVMMUInvocation(_label: MessageLabel, _length: usize, _cptr: usize, _cte: *mut cte_t,
    _cap: &mut cap_t, _call: bool, _buffer: *mut usize,
) -> exception_t {
    panic!("should not be invoked!")
}
