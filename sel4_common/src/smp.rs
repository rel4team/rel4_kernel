use super::sel4_config::{CONFIG_KERNEL_STACK_BITS, CONFIG_MAX_NUM_NODES};
use crate::deps::{coreMap, kernel_stack_alloc};
use crate::BIT;
use core::arch::asm;

#[inline]
fn get_core_map_ref() -> &'static [usize; CONFIG_MAX_NUM_NODES] {
    unsafe { &*(coreMap as usize as *const [usize; CONFIG_MAX_NUM_NODES]) }
}

#[inline]
pub fn cpu_index_to_id(index: usize) -> usize {
    assert!(index < CONFIG_MAX_NUM_NODES);
    unsafe { get_core_map_ref()[index] }
}

#[inline]
pub fn hart_id_to_core_id(hart_id: usize) -> usize {
    unsafe {
        match get_core_map_ref().iter().position(|&x| x == hart_id) {
            Some(core_id) => core_id,
            _ => 0,
        }
    }
}

#[inline]
pub fn get_currenct_cpu_index() -> usize {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let mut cur_sp: usize;
        asm!(
        "csrr {}, sscratch",
        out(reg) cur_sp,
        );
        cur_sp -= kernel_stack_alloc as usize + 8;
        cur_sp >> CONFIG_KERNEL_STACK_BITS
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let mut id: usize;
        asm!(
            "mrs {},tpidr_el1",
            out(reg) id,
        );
        id & 0xfff
    }
}

#[inline]
pub fn get_sbi_mask_for_all_remote_harts() -> usize {
    let mut mask: usize = 0;
    for i in 0..CONFIG_MAX_NUM_NODES {
        if i != get_currenct_cpu_index() {
            mask |= BIT!(cpu_index_to_id(i));
        }
    }
    mask
}
