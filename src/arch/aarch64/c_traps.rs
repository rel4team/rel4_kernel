use super::read_scause;
use crate::{
    config::{
        RISCVInstructionAccessFault, RISCVInstructionPageFault, RISCVLoadAccessFault,
        RISCVLoadPageFault, RISCVStoreAccessFault, RISCVStorePageFault,
    },
    syscall::slowpath,
};

use sel4_task::*;

use super::exception::{handleUserLevelFault, handleVMFaultEvent};
use crate::interrupt::handler::handleInterruptEntry;

#[cfg(feature = "ENABLE_SMP")]
use crate::{
    deps::{clh_is_self_in_queue, clh_lock_acquire, clh_lock_release},
    interrupt::getActiveIRQ,
};

#[cfg(feature = "ENABLE_SMP")]
use sel4_common::utils::cpu_id;

#[no_mangle]
pub fn restore_user_context() {
    unsafe {
        // debug!("restore_user_context");
        let _cur_thread_reg: usize = get_currenct_thread().tcbArch.registers.as_ptr() as usize;
        #[cfg(feature = "ENABLE_SMP")]
        {
            if clh_is_self_in_queue() {
                clh_lock_release(cpu_id());
            }
            // debug!("restore_user_context2");
            let mut cur_sp: usize = 8;
            asm!(
                "csrr {}, sscratch",
                out(reg) cur_sp,
            );
            // debug!("cur_sp: {:#x}", cur_sp);
            *((cur_sp - 8) as *mut usize) = cur_thread_reg;
        }
        // debug!("restore_user_context3");
        unimplemented!("restore_user_context");
        // asm!("mv t0, {0}      \n",
        // "ld  ra, (0*8)(t0)  \n",
        // "ld  sp, (1*8)(t0)  \n",
        // "ld  gp, (2*8)(t0)  \n",
        // "ld  t2, (6*8)(t0)  \n",
        // "ld  s0, (7*8)(t0)  \n",
        // "ld  s1, (8*8)(t0)  \n",
        // "ld  a0, (9*8)(t0)  \n",
        // "ld  a1, (10*8)(t0) \n",
        // "ld  a2, (11*8)(t0) \n",
        // "ld  a3, (12*8)(t0) \n",
        // "ld  a4, (13*8)(t0) \n",
        // "ld  a5, (14*8)(t0) \n",
        // "ld  a6, (15*8)(t0) \n",
        // "ld  a7, (16*8)(t0) \n",
        // "ld  s2, (17*8)(t0) \n",
        // "ld  s3, (18*8)(t0) \n",
        // "ld  s4, (19*8)(t0) \n",
        // "ld  s5, (20*8)(t0) \n",
        // "ld  s6, (21*8)(t0) \n",
        // "ld  s7, (22*8)(t0) \n",
        // "ld  s8, (23*8)(t0) \n",
        // "ld  s9, (24*8)(t0) \n",
        // "ld  s10, (25*8)(t0)\n",
        // "ld  s11, (26*8)(t0)\n",
        // "ld  t3, (27*8)(t0) \n",
        // "ld  t4, (28*8)(t0) \n",
        // "ld  t5, (29*8)(t0) \n",
        // "ld  t6, (30*8)(t0) \n",
        // "ld  t1, (3*8)(t0)  \n",
        // "add tp, t1, x0  \n",
        // "ld  t1, (34*8)(t0)\n",
        // "csrw sepc, t1", in(reg) cur_thread_reg);

        // #[cfg(not(feature = "ENABLE_SMP"))] {
        //     asm!(
        //     "csrw sscratch, t0"
        //     )
        // }
        // asm!(
        // "ld  t1, (32*8)(t0) \n",
        // "csrw sstatus, t1\n",
        // "ld  t1, (5*8)(t0) \n",
        // "ld  t0, (4*8)(t0) \n",
        // "sret");
        // panic!("unreachable")
    }
}

#[no_mangle]
pub fn c_handle_interrupt() {
    // debug!("c_handle_interrupt");
    // if hart_id() != 0 {
    //     debug!("c_handle_interrupt");
    // }
    #[cfg(feature = "ENABLE_SMP")]
    {
        use crate::config::INTERRUPT_IPI_0;
        if getActiveIRQ() != INTERRUPT_IPI_0 {
            unsafe {
                clh_lock_acquire(cpu_id(), true);
            }
        }
    }
    // debug!("c_handle_interrupt");
    handleInterruptEntry();
    restore_user_context();
}

#[no_mangle]
pub fn c_handle_exception() {
    #[cfg(feature = "ENABLE_SMP")]
    unsafe {
        clh_lock_acquire(cpu_id(), false);
    }
    // if hart_id() == 0 {
    //     debug!("c_handle_exception");
    // }

    let cause = read_scause();
    match cause {
        RISCVInstructionAccessFault
        | RISCVLoadAccessFault
        | RISCVStoreAccessFault
        | RISCVLoadPageFault
        | RISCVStorePageFault
        | RISCVInstructionPageFault => {
            handleVMFaultEvent(cause);
        }
        _ => {
            handleUserLevelFault(cause, 0);
        }
    }
    restore_user_context();
}

#[no_mangle]
pub fn c_handle_syscall(_cptr: usize, _msgInfo: usize, syscall: usize) {
    #[cfg(feature = "ENABLE_SMP")]
    unsafe {
        clh_lock_acquire(cpu_id(), false);
    }
    // if hart_id() == 0 {
    //     debug!("c_handle_syscall: syscall: {},", syscall as isize);
    // }
    slowpath(syscall);
    // debug!("c_handle_syscall complete");
}
