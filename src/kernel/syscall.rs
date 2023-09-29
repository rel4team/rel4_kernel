use crate::{
    config::irqInvalid,
    object::interrupt::handleInterrupt,
    riscv::read_sip, interrupt::getActiveIRQ,
};
use super::{
    boot::current_fault,
    faulthandler::handleFault,
    vspace::handleVMFault,
};

use common::{structures::exception_t, fault::*};
use log::debug;
use task_manager::*;


#[no_mangle]
pub fn handleInterruptEntry() -> exception_t {
    let irq = getActiveIRQ();
    if irq != irqInvalid {
        handleInterrupt(irq);
    } else {
        debug!("Spurious interrupt!");
        debug!("Superior IRQ!! SIP {:#x}\n", read_sip());
    }

    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn handleUserLevelFault(w_a: usize, w_b: usize) -> exception_t {
    unsafe {
        current_fault = seL4_Fault_UserException_new(w_a, w_b);
        handleFault(ksCurThread);
    }
    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn handleVMFaultEvent(vm_faultType: usize) -> exception_t {
    let status = unsafe { handleVMFault(ksCurThread, vm_faultType) };
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            handleFault(ksCurThread);
        }
    }
    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn handleYield() {
    get_currenct_thread().sched_dequeue();
    get_currenct_thread().sched_append();
    rescheduleRequired();
}

