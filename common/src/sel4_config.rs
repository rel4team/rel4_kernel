use crate::{BIT, MASK};

pub const wordRadix: usize = 6;
pub const wordBits: usize = BIT!(wordRadix);
pub const seL4_EndpointBits: usize = 4;
pub const seL4_NotificationBits: usize = 4;
pub const seL4_SlotBits: usize = 5;
pub const seL4_ReplyBits: usize = 4;
pub const seL4_MinUntypedBits: usize = 4;
pub const seL4_MaxUntypedBits: usize = 38;

// page table relevant
pub const PT_SIZE_BITS: usize = 12;
pub const PAGE_BITS: usize = seL4_PageBits;
pub const RISCV_4K_Page: usize = 0;
pub const RISCV_Mega_Page: usize = 1;
pub const RISCV_Giga_Page: usize = 2;
pub const RISCV_Tera_Page: usize = 3;

pub const RISCVPageBits: usize = 12;
pub const RISCVMegaPageBits: usize = 21;
pub const RISCVGigaPageBits: usize = 30;

pub const PT_INDEX_BITS: usize = 9;
pub const CONFIG_PT_LEVELS: usize = 3;
pub const seL4_PageBits: usize = 12;
pub const seL4_PageTableBits: usize = 12;


// ASID relevant
pub const asidLowBits: usize = 9;
pub const asidHighBits: usize = 7;
pub const asidInvalid: usize = 0;
pub const nASIDPools: usize = BIT!(asidHighBits);
pub const ASID_BITS: usize = asidHighBits + asidLowBits;
pub const IT_ASID: usize = 1;

// boot 相关的常数
pub const PPTR_TOP: usize = 0xFFFFFFFF80000000;
pub const physBase: usize = 0x80000000;
pub const KERNEL_ELF_PADDR_BASE: usize = physBase + 0x4000000;
pub const KERNEL_ELF_BASE: usize = PPTR_TOP + (KERNEL_ELF_PADDR_BASE & MASK!(30));
pub const KERNEL_ELF_BASE_OFFSET: usize = KERNEL_ELF_BASE - KERNEL_ELF_PADDR_BASE;
pub const PPTR_BASE: usize = 0xFFFFFFC000000000;
pub const PADDR_BASE: usize = 0x0;
pub const PPTR_BASE_OFFSET: usize = PPTR_BASE - PADDR_BASE;
pub const PADDR_TOP: usize = PPTR_TOP - PPTR_BASE_OFFSET;

// lookup_fault
pub const lookup_fault_invalid_root: usize = 0;
pub const lookup_fault_missing_capability: usize = 1;
pub const lookup_fault_depth_mismatch: usize = 2;
pub const lookup_fault_guard_mismatch: usize = 3;