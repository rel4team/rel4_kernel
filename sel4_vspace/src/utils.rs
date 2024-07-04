use super::structures::paddr_t;
use sel4_common::sel4_config::{
    seL4_PageBits, CONFIG_PT_LEVELS, KERNEL_ELF_BASE_OFFSET, PPTR_BASE_OFFSET, PT_INDEX_BITS,
};
use sel4_common::utils::pageBitsForSize;
use sel4_common::{BIT, MASK};

#[inline]
pub fn RISCV_GET_PT_INDEX(addr: usize, n: usize) -> usize {
    ((addr) >> (((PT_INDEX_BITS) * (((CONFIG_PT_LEVELS) - 1) - (n))) + seL4_PageBits))
        & MASK!(PT_INDEX_BITS)
}

#[inline]
pub fn RISCV_GET_LVL_PGSIZE_BITS(n: usize) -> usize {
    ((PT_INDEX_BITS) * (((CONFIG_PT_LEVELS) - 1) - (n))) + seL4_PageBits
}

#[inline]
pub fn RISCV_GET_LVL_PGSIZE(n: usize) -> usize {
    BIT!(RISCV_GET_LVL_PGSIZE_BITS(n))
}

#[inline]
pub fn kpptr_to_paddr(x: usize) -> paddr_t {
    x - KERNEL_ELF_BASE_OFFSET
}

#[inline]
pub fn pptr_to_paddr(x: usize) -> paddr_t {
    x - PPTR_BASE_OFFSET
}

#[inline]
pub fn paddr_to_pptr(x: usize) -> paddr_t {
    x + PPTR_BASE_OFFSET
}

#[inline]
#[no_mangle]
pub fn checkVPAlignment(sz: usize, w: usize) -> bool {
    w & MASK!(pageBitsForSize(sz)) == 0
}
