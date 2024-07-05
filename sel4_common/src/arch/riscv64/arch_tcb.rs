use crate::ffi::kernel_stack_alloc;
// use crate::idle_thread;
use super::{fault_messages, msgRegister, NextIP};
use super::{sp, CONTEXT_REG_NUM, SSTATUS, SSTATUS_SPIE, SSTATUS_SPP};
use crate::sel4_config::CONFIG_KERNEL_STACK_BITS;
use crate::BIT;

/// This is `arch_tcb_t` in the sel4_c_impl.
#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
pub struct ArchTCB {
    pub(in crate::arch) registers: [usize; CONTEXT_REG_NUM],
}

impl Default for ArchTCB {
    fn default() -> Self {
        let mut registers = [0; CONTEXT_REG_NUM];
        registers[SSTATUS] = 0x00040020;
        Self { registers }
    }
}

impl ArchTCB {
    /// Config the registers fot the idle thread.
    pub fn config_idle_thread(&mut self, idle_thread: usize) {
        self.registers[NextIP] = idle_thread;
        self.registers[SSTATUS] = SSTATUS_SPP | SSTATUS_SPIE;
        self.registers[sp] = kernel_stack_alloc as usize + BIT!(CONFIG_KERNEL_STACK_BITS);
    }
}
