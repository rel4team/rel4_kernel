use riscv::register::satp;

use crate::structures::paddr_t;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct satp_t {
    pub words: usize,
}

impl satp_t {
    pub fn new(mode: usize, asid: usize, ppn: usize) -> Self {
        satp_t {
            words: 0
            | (mode & 0xfusize) << 60
            | (asid & 0xffffusize) << 44
            | (ppn & 0xfffffffffffusize) << 0,
        }
    }
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
    let satp = satp_t::new(8usize, asid, addr >> 12);
    satp::write(satp.words);
    sfence();
}