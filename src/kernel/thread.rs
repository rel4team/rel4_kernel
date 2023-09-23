use crate::config::{
    CONFIG_KERNEL_STACK_BITS, SSTATUS_SPIE, SSTATUS_SPP,
};

use task_manager::*;

use core::arch::asm;
use common::{utils::convert_to_type_ref, structures::seL4_IPCBuffer};

use super::boot::{current_lookup_fault, current_syscall_error};

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
pub fn doNBRecvFailedTransfer(thread: *mut tcb_t) {
    setRegister(thread, badgeRegister, 0);
}

#[no_mangle]
pub fn setMR(receiver: *mut tcb_t, receivedBuffer: *mut usize, offset: usize, reg: usize) -> usize {
    if offset >= n_msgRegisters {
        if receivedBuffer as usize != 0 {
            let ptr = unsafe { receivedBuffer.add(offset + 1) };
            unsafe {
                *ptr = reg;
            }
            return offset + 1;
        } else {
            return n_msgRegisters;
        }
    } else {
        setRegister(receiver, msgRegister[offset], reg);
        return offset + 1;
    }
}

pub fn Arch_initContext() -> arch_tcb_t {
   arch_tcb_t::default()
}

#[no_mangle]
pub fn getExtraCPtr(bufferPtr: *mut usize, i: usize) -> usize {
    convert_to_type_ref::<seL4_IPCBuffer>(bufferPtr as usize).get_extra_cptr(i)
}

#[no_mangle]
pub fn setMRs_syscall_error(thread: *mut tcb_t, receivedIPCBuffer: *mut usize) -> usize {
    unsafe {
        match current_syscall_error._type {
            seL4_InvalidArgument => setMR(
                thread,
                receivedIPCBuffer,
                0,
                current_syscall_error.invalidArgumentNumber,
            ),
            seL4_InvalidCapability => setMR(
                thread,
                receivedIPCBuffer,
                0,
                current_syscall_error.invalidCapNumber,
            ),
            seL4_RangeError => {
                setMR(
                    thread,
                    receivedIPCBuffer,
                    0,
                    current_syscall_error.rangeErrorMin,
                );
                setMR(
                    thread,
                    receivedIPCBuffer,
                    1,
                    current_syscall_error.rangeErrorMax,
                )
            }
            seL4_FailedLookup => {
                let flag = if current_syscall_error.failedLookupWasSource == 1 {
                    true
                } else {
                    false
                };
                setMR(thread, receivedIPCBuffer, 0, flag as usize);
                return (*thread).set_lookup_fault_mrs(1, &current_lookup_fault);
            }
            seL4_IllegalOperation
            | seL4_AlignmentError
            | seL4_TruncatedMessage
            | seL4_DeleteFirst
            | seL4_RevokeFirst => 0,
            seL4_NotEnoughMemory => setMR(
                thread,
                receivedIPCBuffer,
                0,
                current_syscall_error.memoryLeft,
            ),
            _ => panic!("invalid syscall error"),
        }
    }
}