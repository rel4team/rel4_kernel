use crate::idle_thread;
use sel4_common::arch::{CONTEXT_REG_NUM, ELR_EL1, SPSR_EL1};

/// This is `arch_tcb_t` in the sel4_c_impl.
#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct ArchTCB {
    registers: [usize; CONTEXT_REG_NUM],
}

/// Implements the Default for the `ArchTCB`
impl Default for ArchTCB {
    fn default() -> Self {
        let mut registers = [0; CONTEXT_REG_NUM];
        registers[SPSR_EL1] = (1 << 6) | 5 | (1 << 8);
        Self { registers }
    }
}
impl ArchTCB {
	/// Set the register of the TCB
    /// # Arguments
    /// * `reg` - The register index.
    /// * `w` - The value to set.
    pub fn set_register(&mut self, reg: usize, w: usize) {
        self.registers[reg] = w;
    }
	/// Get the register value of the TCB
    /// # Arguments
    /// * `reg` - The register index.
    /// # Returns
    /// The value of the register.
    pub fn get_register(&self, reg: usize) -> usize {
        self.registers[reg]
    }

    /// Config the registers fot the idle thread.
    pub fn config_idle_thread(&mut self) {
        self.set_register(ELR_EL1, idle_thread as usize);
        self.set_register(SPSR_EL1, (1 << 6) | 5 | (1 << 8));
    }
}
