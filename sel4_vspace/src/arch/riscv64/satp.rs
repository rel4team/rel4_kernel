use crate::structures::paddr_t;
use riscv::register::satp;
#[cfg(feature = "ENABLE_SMP")]
use sel4_common::arch::remote_sfence_vma;

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

#[cfg(feature = "ENABLE_SMP")]
#[inline]
pub fn sfence() {
    use sel4_common::smp::get_sbi_mask_for_all_remote_harts;

    unsafe {
        core::arch::asm!("fence w, rw");
    }
    sfence_local();
    let mask = get_sbi_mask_for_all_remote_harts();
    remote_sfence_vma(mask, 0, 0);
}

#[cfg(feature = "ENABLE_SMP")]
#[inline]
pub fn sfence_local() {
    unsafe {
        core::arch::asm!("sfence.vma");
    }
}

#[cfg(not(feature = "ENABLE_SMP"))]
#[inline]
pub fn sfence() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("sfence.vma");
    }
}

#[inline]
#[no_mangle]
pub fn setVSpaceRoot(addr: paddr_t, asid: usize) {
    let satp = satp_t::new(8usize, asid, addr >> 12);
    satp::write(satp.words);
    #[cfg(not(feature = "ENABLE_SMP"))]
    sfence();
    #[cfg(feature = "ENABLE_SMP")]
    sfence_local();
}
