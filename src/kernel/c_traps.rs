use core::arch::asm;

use crate::{
    config::{
        RISCVInstructionAccessFault, RISCVInstructionPageFault, RISCVLoadAccessFault,
        RISCVLoadPageFault, RISCVStoreAccessFault, RISCVStorePageFault,
    },
    riscv::read_scause, syscall::slowpath,
};

use task_manager::*;

use super::syscall::{
    handleInterruptEntry, handleUserLevelFault, handleVMFaultEvent,
};

#[no_mangle]
pub fn restore_user_context() {
    unsafe {
        let cur_thread_reg = (*(ksCurThread as *const tcb_t)).tcbArch.registers.as_ptr() as usize;
        asm!("mv t0, {0}      \n",
        "ld  ra, (0*8)(t0)  \n",
        "ld  sp, (1*8)(t0)  \n",
        "ld  gp, (2*8)(t0)  \n",
        "ld  t2, (6*8)(t0)  \n",
        "ld  s0, (7*8)(t0)  \n",
        "ld  s1, (8*8)(t0)  \n",
        "ld  a0, (9*8)(t0)  \n",
        "ld  a1, (10*8)(t0) \n",
        "ld  a2, (11*8)(t0) \n",
        "ld  a3, (12*8)(t0) \n",
        "ld  a4, (13*8)(t0) \n",
        "ld  a5, (14*8)(t0) \n",
        "ld  a6, (15*8)(t0) \n",
        "ld  a7, (16*8)(t0) \n",
        "ld  s2, (17*8)(t0) \n",
        "ld  s3, (18*8)(t0) \n",
        "ld  s4, (19*8)(t0) \n",
        "ld  s5, (20*8)(t0) \n",
        "ld  s6, (21*8)(t0) \n",
        "ld  s7, (22*8)(t0) \n",
        "ld  s8, (23*8)(t0) \n",
        "ld  s9, (24*8)(t0) \n",
        "ld  s10, (25*8)(t0)\n",
        "ld  s11, (26*8)(t0)\n",
        "ld  t3, (27*8)(t0) \n",
        "ld  t4, (28*8)(t0) \n",
        "ld  t5, (29*8)(t0) \n",
        "ld  t6, (30*8)(t0) \n",
        "ld  t1, (3*8)(t0)  \n",
        "add tp, t1, x0  \n",
        "ld  t1, (34*8)(t0)\n",
        "csrw sepc, t1  \n",
        "csrw sscratch, t0         \n",
        "ld  t1, (32*8)(t0) \n",
        "csrw sstatus, t1\n",
        "ld  t1, (5*8)(t0) \n",
        "ld  t0, (4*8)(t0) \n",
        "sret",in(reg) cur_thread_reg);
    }
}

#[no_mangle]
pub fn c_handle_interrupt() {
    handleInterruptEntry();
    restore_user_context();
}

#[no_mangle]
pub fn c_handle_exception() {
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
    slowpath(syscall);
}
