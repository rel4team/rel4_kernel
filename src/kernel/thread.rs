use crate::config::{
    CONFIG_KERNEL_STACK_BITS, SSTATUS_SPIE, SSTATUS_SPP,
};

use task_manager::*;

use core::arch::asm;

use common::{BIT, sel4_config::*};

#[no_mangle]
pub static mut kernel_stack_alloc: [[u8; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES] =
    [[0; BIT!(CONFIG_KERNEL_STACK_BITS)]; CONFIG_MAX_NUM_NODES];


pub fn create_idle_thread() {
    unsafe {
        let pptr = ksIdleThreadTCB.as_ptr() as *mut usize;
        ksIdleThread = pptr.add(TCB_OFFSET) as *mut tcb_t;
        // configureIdleThread(ksIdleThread as *const tcb_t);
        let tcb = ksIdleThread as *mut tcb_t;
        setRegister(tcb, NextIP, idle_thread as usize);
        setRegister(tcb, SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
        setRegister(
            tcb,
            sp,
            kernel_stack_alloc.as_ptr() as usize + BIT!(CONFIG_KERNEL_STACK_BITS),
        );
        setThreadState(tcb, ThreadStateIdleThreadState);
    }
}

pub fn idle_thread() {
    unsafe {
        while true {
            asm!("wfi");
        }
    }
}

#[no_mangle]
pub fn configureIdleThread(_tcb: *const tcb_t) {
    panic!("should not be invoked!")
}

#[no_mangle]
pub fn setMR(_receiver: *mut tcb_t, _receivedBuffer: *mut usize, _offset: usize, _reg: usize) -> usize {
    panic!("should not be invoked!")
}
