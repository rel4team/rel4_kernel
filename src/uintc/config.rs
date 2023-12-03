use crate::common::sel4_config::PPTR_BASE;

/// UINTC base
pub const UINTC_BASE: usize = 0x2F1_0000 + PPTR_BASE;

/// UINTC size
pub const UINTC_SIZE: usize = 0x4000;

/// Maximum number of UINTC entries
pub const UINTC_ENTRY_NUM: usize = 512;

/// UINTC register width
pub const UINTC_WIDTH: usize = 32;