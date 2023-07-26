use crate::BIT;

pub const wordRadix: usize = 6;
pub const wordBits: usize = BIT!(wordRadix);
pub const seL4_EndpointBits: usize = 4;
pub const seL4_NotificationBits: usize = 4;
pub const seL4_SlotBits: usize = 5;
pub const seL4_ReplyBits: usize = 4;
pub const seL4_MinUntypedBits: usize = 4;
pub const seL4_MaxUntypedBits: usize = 38;

pub const PT_SIZE_BITS: usize = 12;


// page table relevant
pub const RISCV_4K_Page: usize = 0;
pub const RISCV_Mega_Page: usize = 1;
pub const RISCV_Giga_Page: usize = 2;
pub const RISCV_Tera_Page: usize = 3;

pub const RISCVPageBits: usize = 12;
pub const RISCVMegaPageBits: usize = 21;
pub const RISCVGigaPageBits: usize = 30;
