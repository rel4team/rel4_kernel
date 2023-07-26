use common::{utils::{convert_to_mut_type_ref, convert_to_type_ref}, MASK};

use crate::config::{seL4_PageTableBits, CONFIG_PT_LEVELS, PT_INDEX_BITS, seL4_PageBits};

use super::{vptr_t, paddr_to_pptr};

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct pte_t {
    pub words: [usize; 1],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct lookupPTSlot_ret_t {
    pub ptSlot: *mut pte_t,
    pub ptBitsLeft: usize,
}

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


impl pte_t {
    pub fn new(ppn: usize, sw: usize, dirty: usize, accessed: usize, global: usize, user: usize, execute: usize, write: usize,
        read: usize, valid: usize) -> Self {
        
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

    pub fn pte_next(phys_addr: usize, is_leaf: bool) -> Self {
        let ppn = (phys_addr >> 12) as usize;

        let read = is_leaf as u8;
        let write = read;
        let exec = read;
        Self::new(
            ppn, 0, is_leaf as usize, is_leaf as usize, 1,
            0, exec as usize, write as usize,read as usize, 1
        )
    }

    pub fn pte_invalid() -> Self {
        pte_t { words: [0] }
    }

    pub fn is_pte_table(&self) -> bool {
        self.get_vaild() != 0 && !(self.get_read() != 0 ||self.get_write() != 0 || self.get_execute() != 0)
    }

    pub fn get_pte_from_ppn_mut(&self) -> &'static mut Self {
        convert_to_mut_type_ref::<pte_t>(paddr_to_pptr(self.get_ppn() << seL4_PageTableBits))
    }

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

        while unsafe {(*ret.ptSlot).is_pte_table()} && level > 0 {
            level -= 1;
            ret.ptBitsLeft -= PT_INDEX_BITS;
            pt = unsafe {(*ret.ptSlot).get_pte_from_ppn_mut() as *mut pte_t};
            ret.ptSlot = unsafe { pt.add((vptr >> ret.ptBitsLeft) & MASK!(PT_INDEX_BITS)) };
        }
        ret
    }

    pub fn get_vaild(&self) -> usize {
        (self.words[0] & 0x1) >> 0
    }

    pub fn get_ppn(&self) -> usize {
        (self.words[0] & 0x3f_ffff_ffff_fc00usize) >> 10
    }

    pub fn get_execute(&self) -> usize {
        (self.words[0] & 0x8usize) >> 3
    }

    pub fn get_write(&self) -> usize {
        (self.words[0] & 0x4usize) >> 2
    }

    pub fn get_read(&self) -> usize {
        (self.words[0] & 0x2usize) >> 1
    }
}


#[inline]
pub fn pte_ptr_get_valid(pte_ptr: *const pte_t) -> usize {
    unsafe {
        (*pte_ptr).get_vaild()
    }
}

#[inline]
pub fn pte_ptr_get_ppn(pte_ptr: *const pte_t) -> usize {
    unsafe {
        (*pte_ptr).get_ppn()
    }
}
#[inline]
pub fn pte_ptr_get_execute(pte_ptr: *const pte_t) -> usize {
    unsafe {
        (*pte_ptr).get_execute()
    }
}

#[inline]
pub fn pte_ptr_get_write(pte_ptr: *const pte_t) -> usize {
    unsafe {
        (*pte_ptr).get_write()
    }
}

#[inline]
pub fn pte_ptr_get_read(pte_ptr: *const pte_t) -> usize {
    unsafe {
        (*pte_ptr).get_read()
    }
}