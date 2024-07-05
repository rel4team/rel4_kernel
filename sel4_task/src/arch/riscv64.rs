use crate::deps::kernel_stack_alloc;
use crate::idle_thread;
use sel4_common::arch::NextIP;
use sel4_common::arch::{sp, CONTEXT_REG_NUM, SSTATUS, SSTATUS_SPIE, SSTATUS_SPP};
use sel4_common::sel4_config::CONFIG_KERNEL_STACK_BITS;
use sel4_common::BIT;

/// This is `arch_tcb_t` in the sel4_c_impl.
#[repr(C)]
#[derive(Debug, PartialEq, Clone)]
pub struct ArchTCB {
    pub registers: [usize; CONTEXT_REG_NUM],
}

impl Default for ArchTCB {
    fn default() -> Self {
        let mut registers = [0; CONTEXT_REG_NUM];
        registers[SSTATUS] = 0x00040020;
        Self { registers }
    }
}

impl ArchTCB {
    /// Set the register of the TCB
    /// # Arguments
    /// * `reg` - The register index.
    /// * `w` - The value to set.
    #[inline]
    pub fn set_register(&mut self, reg: usize, w: usize) {
        self.registers[reg] = w;
    }
    /// Get the register value of the TCB
    /// # Arguments
    /// * `reg` - The register index.
    /// # Returns
    /// The value of the register.
    #[inline]
    pub fn get_register(&self, reg: usize) -> usize {
        self.registers[reg]
    }

    /// Config the registers fot the idle thread.
    pub fn config_idle_thread(&mut self) {
        self.set_register(NextIP, idle_thread as usize);
        self.set_register(SSTATUS, SSTATUS_SPP | SSTATUS_SPIE);
        self.set_register(
            sp,
            kernel_stack_alloc as usize + BIT!(CONFIG_KERNEL_STACK_BITS),
        );
    }
}
