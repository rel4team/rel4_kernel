mod pte;
mod utils;
mod structures;
mod asid;

use common::BIT;
pub use utils::{
    RISCV_GET_LVL_PGSIZE, RISCV_GET_LVL_PGSIZE_BITS, RISCV_GET_PT_INDEX,
    paddr_to_pptr, pptr_to_paddr, kpptr_to_paddr
};
pub use pte::{pte_t, satp_t};
pub use structures::{paddr_t, vptr_t, pptr_t};
pub use asid::{asid_pool_t, findVSpaceForASID, asid_t, hwASIDFlush};
use riscv::register::satp;

use crate::{config::{PT_INDEX_BITS, PPTR_BASE, PADDR_BASE, PPTR_TOP, KERNEL_ELF_BASE, KERNEL_ELF_PADDR_BASE,
    PPTR_BASE_OFFSET, asidHighBits}, ROUND_DOWN};

pub use pte::{pte_ptr_get_valid, pte_ptr_get_execute, pte_ptr_get_ppn, pte_ptr_get_write, pte_ptr_get_read};

pub use self::pte::lookupPTSlot_ret_t;

#[no_mangle]
#[link_section = ".page_table"]
pub static mut kernel_root_pageTable: [pte_t; BIT!(PT_INDEX_BITS)] =
    [pte_t { words: [0] }; BIT!(PT_INDEX_BITS)];

#[no_mangle]
#[link_section = ".page_table"]
pub static mut kernel_image_level2_pt: [pte_t; BIT!(PT_INDEX_BITS)] =
    [pte_t { words: [0] }; BIT!(PT_INDEX_BITS)];

#[no_mangle]
pub static mut riscvKSASIDTable: [*mut asid_pool_t; BIT!(asidHighBits)] =
    [0 as *mut asid_pool_t; BIT!(asidHighBits)];


#[inline]
pub fn satp_new(mode: usize, asid: usize, ppn: usize) -> satp_t {
    satp_t::new(mode, asid, ppn)
}


#[inline]
pub unsafe fn write_satp(value: usize) {
    core::arch::asm!("csrw satp,{0}",in(reg) value);
}

#[inline]
pub unsafe fn read_satp() -> usize {
    let temp: usize;
    core::arch::asm!("csrr {0},satp",out(reg) temp);
    temp
}

#[inline]
#[no_mangle]
pub fn sfence() {
    unsafe {
        core::arch::asm!("sfence.vma");
    }
}

#[inline]
#[no_mangle]
pub fn setVSpaceRoot(addr: paddr_t, asid: usize) {
    let satp = satp_new(8usize, asid, addr >> 12);
    unsafe {
        satp::write(satp.words);
        sfence();
    }
}


#[inline]
pub fn pte_new(ppn: usize, sw: usize, dirty: usize, accessed: usize, global: usize, user: usize, execute: usize, write: usize,
    read: usize, valid: usize) -> pte_t {
    pte_t::new(ppn, sw, dirty, accessed, global, user, execute, write, read, valid)
}

#[no_mangle]
pub fn pte_pte_invalid_new() -> pte_t {
    pte_t::pte_invalid()
}


#[inline]
#[no_mangle]
pub fn pte_next(phys_addr: usize, is_leaf: bool) -> pte_t {
    pte_t::pte_next(phys_addr, is_leaf)
}

#[no_mangle]
pub fn rust_map_kernel_window() {
    let mut pptr = PPTR_BASE;

    let mut paddr = PADDR_BASE;
    while pptr < PPTR_TOP {
        unsafe {
            kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] = pte_next(paddr, true);
        }
        pptr += RISCV_GET_LVL_PGSIZE(0);
        paddr += RISCV_GET_LVL_PGSIZE(0);
    }
    pptr = ROUND_DOWN!(KERNEL_ELF_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));
    paddr = ROUND_DOWN!(KERNEL_ELF_PADDR_BASE, RISCV_GET_LVL_PGSIZE_BITS(0));
    unsafe {
        kernel_root_pageTable[RISCV_GET_PT_INDEX(KERNEL_ELF_PADDR_BASE + PPTR_BASE_OFFSET, 0)] =
            pte_next(
                kpptr_to_paddr(kernel_image_level2_pt.as_ptr() as usize),
                false,
            );
        kernel_root_pageTable[RISCV_GET_PT_INDEX(pptr, 0)] = pte_next(
            kpptr_to_paddr(kernel_image_level2_pt.as_ptr() as usize),
            false,
        );
    }

    let mut index = 0;
    while pptr < PPTR_TOP + RISCV_GET_LVL_PGSIZE(0) {
        unsafe {
            kernel_image_level2_pt[index] = pte_next(paddr, true);
        }
        pptr += RISCV_GET_LVL_PGSIZE(1);
        paddr += RISCV_GET_LVL_PGSIZE(1);
        index += 1;
    }
}


pub fn activate_kernel_vspace() {
    unsafe {
        setVSpaceRoot(kpptr_to_paddr(kernel_root_pageTable.as_ptr() as usize), 0);
    }
}

#[no_mangle]
pub fn copyGlobalMappings(Lvl1pt: usize) {
    let mut i: usize = RISCV_GET_PT_INDEX(0x80000000, 0);
    while i < BIT!(PT_INDEX_BITS) {
        unsafe {
            let newLvl1pt = (Lvl1pt + i * 8) as *mut usize;
            *newLvl1pt = kernel_root_pageTable[i].words[0];
            i += 1;
        }
    }
}

#[inline]
#[no_mangle]
pub fn isPTEPageTable(pte: *mut pte_t) -> bool {
    unsafe {
        (*pte).is_pte_table()
    }
}


#[inline]
pub fn getPPtrFromHWPTE(pte: *mut pte_t) -> *mut pte_t {
    unsafe {
        (*pte).get_pte_from_ppn_mut() as *mut pte_t
    }
}

#[no_mangle]
pub extern "C" fn lookupPTSlot(lvl1pt: *mut pte_t, vptr: vptr_t) -> lookupPTSlot_ret_t {
    unsafe {
        (*lvl1pt).lookup_pt_slot(vptr)
    }
}
