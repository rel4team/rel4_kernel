use core::intrinsics::unlikely;
use sel4_common::sel4_config::{
    seL4_PageBits, seL4_PageTableBits, CONFIG_PT_LEVELS, PT_INDEX_BITS,
};
use sel4_common::structures::exception_t;
use sel4_common::utils::{convert_to_mut_type_ref, convert_to_type_ref};
use sel4_common::MASK;

use super::satp::sfence;
use crate::asid::{asid_t, find_vspace_for_asid};
use crate::structures::vptr_t;
use crate::utils::{paddr_to_pptr, RISCV_GET_PT_INDEX};
use crate::vm_rights::{RISCVGetReadFromVMRights, RISCVGetWriteFromVMRights};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pte_t {
    pub words: [usize; 1],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct lookupPTSlot_ret_t {
    pub ptSlot: *mut pte_t,
    pub ptBitsLeft: usize,
}

impl pte_t {
    #[inline]
    pub fn get_ptr(&self) -> usize {
        self as *const Self as usize
    }

    #[inline]
    pub fn new(
        ppn: usize,
        sw: usize,
        dirty: usize,
        accessed: usize,
        global: usize,
        user: usize,
        execute: usize,
        write: usize,
        read: usize,
        valid: usize,
    ) -> Self {
        pte_t {
            words: [0
                | (ppn & 0xfffffffffffusize) << 10
                | (sw & 0x3usize) << 8
                | (dirty & 0x1usize) << 7
                | (accessed & 0x1usize) << 6
                | (global & 0x1usize) << 5
                | (user & 0x1usize) << 4
                | (execute & 0x1usize) << 3
                | (write & 0x1usize) << 2
                | (read & 0x1usize) << 1
                | (valid & 0x1usize) << 0],
        }
    }

    #[inline]
    pub fn make_user_pte(paddr: usize, executable: bool, vm_rights: usize) -> Self {
        let write = RISCVGetWriteFromVMRights(vm_rights);
        let read = RISCVGetReadFromVMRights(vm_rights);
        if !executable && !read && !write {
            return Self::pte_invalid();
        }
        Self::new(
            paddr >> seL4_PageBits,
            0,                   /* sw */
            1,                   /* dirty (leaf) */
            1,                   /* accessed (leaf) */
            0,                   /* global */
            1,                   /* user (leaf) */
            executable as usize, /* execute */
            write as usize,      /* write */
            read as usize,       /* read */
            1,                   /* valid */
        )
    }

    #[inline]
    pub fn pte_next(phys_addr: usize, is_leaf: bool) -> Self {
        let ppn = (phys_addr >> 12) as usize;

        let read = is_leaf as u8;
        let write = read;
        let exec = read;
        Self::new(
            ppn,
            0,
            is_leaf as usize,
            is_leaf as usize,
            1,
            0,
            exec as usize,
            write as usize,
            read as usize,
            1,
        )
    }

    #[inline]
    pub fn update(&mut self, pte: Self) {
        *self = pte;
        sfence();
    }

    pub fn unmap_page_table(&mut self, asid: asid_t, vptr: vptr_t) {
        let target_pt = self as *mut pte_t;
        let find_ret = find_vspace_for_asid(asid);
        if find_ret.status != exception_t::EXCEPTION_NONE {
            return;
        }
        assert_ne!(find_ret.vspace_root.unwrap(), target_pt);
        let mut pt = find_ret.vspace_root.unwrap();
        let mut ptSlot = unsafe { &mut *(pt.add(RISCV_GET_PT_INDEX(vptr, 0))) };
        let mut i = 0;
        while i < CONFIG_PT_LEVELS - 1 && pt != target_pt {
            ptSlot = unsafe { &mut *(pt.add(RISCV_GET_PT_INDEX(vptr, i))) };
            if unlikely(ptSlot.is_pte_table()) {
                return;
            }
            pt = ptSlot.get_pte_from_ppn_mut() as *mut pte_t;
            i += 1;
        }

        if pt != target_pt {
            return;
        }
        *ptSlot = pte_t::new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        sfence();
    }

    #[inline]
    pub fn pte_invalid() -> Self {
        pte_t { words: [0] }
    }

    #[inline]
    pub fn is_pte_table(&self) -> bool {
        self.get_vaild() != 0
            && !(self.get_read() != 0 || self.get_write() != 0 || self.get_execute() != 0)
    }

    #[inline]
    pub fn get_pte_from_ppn_mut(&self) -> &'static mut Self {
        convert_to_mut_type_ref::<pte_t>(paddr_to_pptr(self.get_ppn() << seL4_PageTableBits))
    }

    #[inline]
    pub fn get_pte_from_ppn(&self) -> &'static Self {
        convert_to_type_ref::<pte_t>(paddr_to_pptr(self.get_ppn() << seL4_PageTableBits))
    }

    pub fn lookup_pt_slot(&self, vptr: vptr_t) -> lookupPTSlot_ret_t {
        let mut level = CONFIG_PT_LEVELS - 1;
        let mut pt = self as *const pte_t as usize as *mut pte_t;
        let mut ret = lookupPTSlot_ret_t {
            ptBitsLeft: PT_INDEX_BITS * level + seL4_PageBits,
            ptSlot: unsafe {
                pt.add((vptr >> (PT_INDEX_BITS * level + seL4_PageBits)) & MASK!(PT_INDEX_BITS))
            },
        };

        while unsafe { (*ret.ptSlot).is_pte_table() } && level > 0 {
            level -= 1;
            ret.ptBitsLeft -= PT_INDEX_BITS;
            pt = unsafe { (*ret.ptSlot).get_pte_from_ppn_mut() as *mut pte_t };
            ret.ptSlot = unsafe { pt.add((vptr >> ret.ptBitsLeft) & MASK!(PT_INDEX_BITS)) };
        }
        ret
    }

    #[inline]
    pub fn get_vaild(&self) -> usize {
        (self.words[0] & 0x1) >> 0
    }

    #[inline]
    pub fn get_ppn(&self) -> usize {
        (self.words[0] & 0x3f_ffff_ffff_fc00usize) >> 10
    }

    #[inline]
    pub fn get_execute(&self) -> usize {
        (self.words[0] & 0x8usize) >> 3
    }

    #[inline]
    pub fn get_write(&self) -> usize {
        (self.words[0] & 0x4usize) >> 2
    }

    #[inline]
    pub fn get_read(&self) -> usize {
        (self.words[0] & 0x2usize) >> 1
    }
}
