use core::arch::asm;
use riscv::register::satp;

use crate::{
    config::{
        asidHighBits, asidLowBits, seL4_CapInitThreadVspace, seL4_PageBits, seL4_PageTableBits,
        tcbVTable, RISCVGigaPageBits, RISCVMegaPageBits, RISCVPageBits, CONFIG_PT_LEVELS, IT_ASID,
        KERNEL_ELF_BASE, KERNEL_ELF_BASE_OFFSET, KERNEL_ELF_PADDR_BASE, PADDR_BASE, PPTR_BASE,
        PPTR_BASE_OFFSET, PPTR_TOP, PT_INDEX_BITS,
    },
    object::{
        objecttype::{cap_get_capPtr, cap_get_capType, cap_page_table_cap},
        structure_gen::{
            cap_frame_cap_get_capFMappedAddress, cap_frame_cap_new, cap_null_cap_new,
            cap_page_table_cap_get_capPTBasePtr, cap_page_table_cap_get_capPTMappedASID,
            cap_page_table_cap_get_capPTMappedAddress, cap_page_table_cap_new, pte_ptr_get_execute,
            pte_ptr_get_ppn, pte_ptr_get_read, pte_ptr_get_valid, pte_ptr_get_write,
        },
    },
    println,
    structures::{
        asid_pool_t, cap_t, cte_t, lookupPTSlot_ret_t, satp_t, seL4_SlotRegion, tcb_t, v_region_t,
    },
    BIT, MASK, ROUND_DOWN,
};

use super::{
    boot::{it_alloc_paging, ndks_boot, provide_cap, rootserver, write_slot},
    thread::getCSpace,
};

pub type pptr_t = usize;
pub type paddr_t = usize;
pub type vptr_t = usize;
pub type pte_t = usize;
pub type asid_t = usize;
pub type vm_rights_t = usize;

pub fn hwASIDFlush(asid: asid_t) {
    unsafe {
        asm!("sfence.vma x0, {0}",in(reg) asid);
    }
}

#[link_section = ".page_table"]
static mut kernel_root_pageTable: [pte_t; BIT!(PT_INDEX_BITS)] = [0; BIT!(PT_INDEX_BITS)];

#[link_section = ".page_table"]
static mut kernel_image_level2_pt: [pte_t; BIT!(PT_INDEX_BITS)] = [0; BIT!(PT_INDEX_BITS)];

static mut riscvKSASIDTable: [*mut asid_pool_t; BIT!(asidHighBits)] =
    [0 as *mut asid_pool_t; BIT!(asidHighBits)];

#[inline]
pub fn satp_new(mode: usize, asid: usize, ppn: usize) -> satp_t {
    let satp = satp_t {
        words: 0
            | (mode & 0xfusize) << 60
            | (asid & 0xffffusize) << 44
            | (ppn & 0xfffffffffffusize) << 0,
    };
    satp
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
pub unsafe fn sfence() {
    core::arch::asm!("sfence.vma");
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
pub fn pte_new(
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
) -> pte_t {
    let pte = 0
        | (ppn & 0xfffffffffffusize) << 10
        | (sw & 0x3usize) << 8
        | (dirty & 0x1usize) << 7
        | (accessed & 0x1usize) << 6
        | (global & 0x1usize) << 5
        | (user & 0x1usize) << 4
        | (execute & 0x1usize) << 3
        | (write & 0x1usize) << 2
        | (read & 0x1usize) << 1
        | (valid & 0x1usize) << 0;
    pte
}

pub fn pte_next(phys_addr: usize, is_leaf: bool) -> pte_t {
    let ppn = (phys_addr >> 12) as usize;

    let read = is_leaf as u8;
    let write = read;
    let exec = read;
    return pte_new(
        ppn,
        0,                /* sw */
        is_leaf as usize, /* dirty (leaf)/reserved (non-leaf) */
        is_leaf as usize, /* accessed (leaf)/reserved (non-leaf) */
        1,                /* global */
        0,                /* user (leaf)/reserved (non-leaf) */
        exec as usize,    /* execute */
        write as usize,   /* write */
        read as usize,    /* read */
        1,                /* valid */
    );
}

pub fn RISCV_GET_PT_INDEX(addr: usize, n: usize) -> usize {
    ((addr) >> (((PT_INDEX_BITS) * (((CONFIG_PT_LEVELS) - 1) - (n))) + seL4_PageBits))
        & MASK!(PT_INDEX_BITS)
}

fn RISCV_GET_LVL_PGSIZE_BITS(n: usize) -> usize {
    ((PT_INDEX_BITS) * (((CONFIG_PT_LEVELS) - 1) - (n))) + seL4_PageBits
}

fn RISCV_GET_LVL_PGSIZE(n: usize) -> usize {
    BIT!(RISCV_GET_LVL_PGSIZE_BITS(n))
}

pub fn kpptr_to_paddr(x: usize) -> paddr_t {
    x - KERNEL_ELF_BASE_OFFSET
}
pub fn pptr_to_paddr(x: usize) -> paddr_t {
    x - PPTR_BASE_OFFSET
}
pub fn paddr_to_pptr(x: usize) -> paddr_t {
    x + PPTR_BASE_OFFSET
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

pub fn copyGlobalMappings(Lvl1pt: usize) {
    let mut i: usize = RISCV_GET_PT_INDEX(0x80000000, 0);
    while i < BIT!(PT_INDEX_BITS) {
        unsafe {
            let newLvl1pt = (Lvl1pt + i * 8) as *mut usize;
            *newLvl1pt = kernel_root_pageTable[i];
            i += 1;
        }
    }
}

#[inline]
pub fn isPTEPageTable(_pte: usize) -> bool {
    let pte = _pte as *const usize;
    pte_ptr_get_valid(pte) != 0
        && !(pte_ptr_get_read(pte) != 0
            || pte_ptr_get_write(pte) != 0
            || pte_ptr_get_execute(pte) != 0)
}

pub fn lookupPTSlot(lvl1pt: usize, vptr: vptr_t) -> lookupPTSlot_ret_t {
    let mut level = CONFIG_PT_LEVELS - 1;
    let mut pt = lvl1pt;
    let mut ret = lookupPTSlot_ret_t {
        ptBitsLeft: PT_INDEX_BITS * level + seL4_PageBits,
        ptSlot: pt + ((vptr >> (PT_INDEX_BITS * level + seL4_PageBits)) & MASK!(PT_INDEX_BITS)) * 8,
    };
    while isPTEPageTable(ret.ptSlot) && level > 0 {
        level -= 1;
        ret.ptBitsLeft -= PT_INDEX_BITS;
        pt = getPPtrFromHWPTE(ret.ptSlot);
        ret.ptSlot = pt + ((vptr >> ret.ptBitsLeft) & MASK!(PT_INDEX_BITS)) * 8;
    }
    ret
}

#[inline]
pub fn getPPtrFromHWPTE(pte: usize) -> usize {
    paddr_to_pptr(pte_ptr_get_ppn(pte as *const usize) << seL4_PageTableBits)
}

pub fn map_it_pt_cap(_vspace_cap: &cap_t, _pt_cap: &cap_t) {
    let vptr = cap_page_table_cap_get_capPTMappedAddress(_pt_cap);
    let lvl1pt = cap_get_capPtr(_vspace_cap);
    let pt: usize = cap_get_capPtr(_pt_cap);
    let pt_ret = lookupPTSlot(lvl1pt, vptr);
    let targetSlot = pt_ret.ptSlot as *mut usize;
    unsafe {
        *targetSlot = pte_new(
            pptr_to_paddr(pt) >> seL4_PageBits,
            0, /* sw */
            0, /* dirty (reserved non-leaf) */
            0, /* accessed (reserved non-leaf) */
            0, /* global */
            0, /* user (reserved non-leaf) */
            0, /* execute */
            0, /* write */
            0, /* read */
            1, /* valid */
        );
        sfence();
    }
}

pub fn create_it_pt_cap(vspace_cap: &cap_t, pptr: pptr_t, vptr: vptr_t, asid: usize) -> cap_t {
    let cap = cap_page_table_cap_new(asid, pptr, 1, vptr);
    map_it_pt_cap(vspace_cap, &cap);
    return cap;
}

pub fn map_it_frame_cap(_vspace_cap: &cap_t, _frame_cap: &cap_t) {
    let vptr = cap_frame_cap_get_capFMappedAddress(_frame_cap);
    let lvl1pt = cap_get_capPtr(_vspace_cap);
    let frame_pptr: usize = cap_get_capPtr(_frame_cap);
    let pt_ret = lookupPTSlot(lvl1pt, vptr);

    let targetSlot = pt_ret.ptSlot as *mut usize;
    unsafe {
        *targetSlot = pte_new(
            pptr_to_paddr(frame_pptr) >> seL4_PageBits,
            0, /* sw */
            1, /* dirty (reserved non-leaf) */
            1, /* accessed (reserved non-leaf) */
            0, /* global */
            1, /* user (reserved non-leaf) */
            1, /* execute */
            1, /* write */
            1, /* read */
            1, /* valid */
        );
        sfence();
    }
}

pub fn rust_create_it_address_space(root_cnode_cap: &cap_t, it_v_reg: v_region_t) -> cap_t {
    unsafe {
        copyGlobalMappings(rootserver.vspace);
        let lvl1pt_cap = cap_page_table_cap_new(IT_ASID, rootserver.vspace, 1, rootserver.vspace);
        let ret = cap_page_table_cap_get_capPTMappedAddress(&lvl1pt_cap);
        let ptr = cap_get_capPtr(root_cnode_cap) as *mut cte_t;
        let slot_pos_before = ndks_boot.slot_pos_cur;
        write_slot(ptr.add(seL4_CapInitThreadVspace), lvl1pt_cap.clone());
        let mut i = 0;
        while i < CONFIG_PT_LEVELS - 1 {
            let mut pt_vptr = ROUND_DOWN!(it_v_reg.start, RISCV_GET_LVL_PGSIZE_BITS(i));
            while pt_vptr < it_v_reg.end {
                if !provide_cap(
                    root_cnode_cap,
                    create_it_pt_cap(&lvl1pt_cap, it_alloc_paging(), pt_vptr, IT_ASID),
                ) {
                    return cap_null_cap_new();
                }
                pt_vptr += RISCV_GET_LVL_PGSIZE(i);
            }
            i += 1;
        }
        let slot_pos_after = ndks_boot.slot_pos_cur;
        (*ndks_boot.bi_frame).userImagePaging = seL4_SlotRegion {
            start: slot_pos_before,
            end: slot_pos_after,
        };
        lvl1pt_cap
    }
}

pub fn rust_create_unmapped_it_frame_cap(pptr: pptr_t, _use_large: bool) -> cap_t {
    cap_frame_cap_new(0, pptr, 0, 0, 0, 0)
}

pub fn write_it_asid_pool(it_ap_cap: &cap_t, it_lvl1pt_cap: &cap_t) {
    let ap = cap_get_capPtr(it_ap_cap);
    unsafe {
        let ptr = (ap + 8 * IT_ASID) as *mut usize;
        *ptr = cap_get_capPtr(it_lvl1pt_cap);
        riscvKSASIDTable[IT_ASID >> asidLowBits] = ap as *mut asid_pool_t;
    }
}

pub fn setVMRoot(thread: *mut tcb_t) {
    unsafe {
        let threadRoot = &(*getCSpace(thread as usize, tcbVTable)).cap;
        if cap_get_capType(threadRoot) != cap_page_table_cap {
            setVSpaceRoot(kpptr_to_paddr(kernel_root_pageTable.as_ptr() as usize), 0);
            return;
        }
        let lvl1pt = cap_page_table_cap_get_capPTBasePtr(threadRoot);
        let asid = cap_page_table_cap_get_capPTMappedASID(threadRoot);
        setVSpaceRoot(pptr_to_paddr(lvl1pt), asid);
    }
}

#[inline]
pub fn pageBitsForSize(page_size: usize) -> usize {
    match page_size {
        RISCV_4K_Page => RISCVPageBits,
        RISCV_Mega_Page => RISCVMegaPageBits,
        RISCV_Giga_Page => RISCVGigaPageBits,
        _ => panic!("Invalid page size!"),
    }
}
