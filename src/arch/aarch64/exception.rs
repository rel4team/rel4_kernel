use super::read_stval;
use crate::config::*;
use crate::kernel::boot::current_fault;
use crate::syscall::handle_fault;
use sel4_common::fault::seL4_Fault_t;
use sel4_common::structures::exception_t;
use sel4_task::{activateThread, get_currenct_thread, schedule};

#[no_mangle]
pub fn handleUserLevelFault(w_a: usize, w_b: usize) -> exception_t {
    unsafe {
        current_fault = seL4_Fault_t::new_user_exeception(w_a, w_b);
        handle_fault(get_currenct_thread());
    }
    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn handleVMFaultEvent(vm_faultType: usize) -> exception_t {
    let status = handle_vm_fault(vm_faultType);
    if status != exception_t::EXCEPTION_NONE {
        // debug!("handle_fault: {}", vm_faultType);
        handle_fault(get_currenct_thread());
    }
    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

pub fn handle_vm_fault(type_: usize) -> exception_t {
    let addr = read_stval();
    match type_ {
        RISCVLoadPageFault | RISCVLoadAccessFault => {
            unsafe {
                current_fault = seL4_Fault_t::new_vm_fault(addr, RISCVLoadAccessFault, 0);
            }
            exception_t::EXCEPTION_FAULT
        }
        RISCVStorePageFault | RISCVStoreAccessFault => {
            unsafe {
                current_fault = seL4_Fault_t::new_vm_fault(addr, RISCVStoreAccessFault, 0);
            }
            exception_t::EXCEPTION_FAULT
        }
        RISCVInstructionAccessFault | RISCVInstructionPageFault => {
            unsafe {
                current_fault = seL4_Fault_t::new_vm_fault(addr, RISCVInstructionAccessFault, 1);
            }
            exception_t::EXCEPTION_FAULT
        }
        _ => panic!("Invalid VM fault type:{}", type_),
    }
}
