#![feature(core_intrinsics)]
#![no_std]
#![allow(internal_features)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub mod arch;
mod asid;
pub mod interface;
mod structures;
mod utils;
mod vm_rights;

pub use arch::pte_t;
#[cfg(target_arch = "riscv64")]
pub use arch::satp::{setVSpaceRoot, sfence};
pub use asid::{
    asid_pool_t, asid_t, delete_asid, delete_asid_pool, find_vspace_for_asid,
    get_asid_pool_by_index, riscvKSASIDTable, set_asid_pool_by_index,
};
pub use interface::{
    activate_kernel_vspace, copyGlobalMappings, rust_map_kernel_window, set_vm_root, unmapPage,
};
pub use structures::*;
pub use utils::{
    checkVPAlignment, kpptr_to_paddr, paddr_to_pptr, pptr_to_paddr, RISCV_GET_LVL_PGSIZE,
    RISCV_GET_LVL_PGSIZE_BITS,
};
pub use vm_rights::{maskVMRights, VMReadOnly, VMReadWrite};
