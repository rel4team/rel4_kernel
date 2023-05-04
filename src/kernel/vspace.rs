use core::{arch::asm, intrinsics::unlikely, mem::forget};
use riscv::register::satp;

use crate::{
    config::{
        asidHighBits, asidInvalid, asidLowBits, badgeRegister, msgInfoRegister, nASIDPools,
        n_msgRegisters, seL4_ASIDPoolBits, seL4_AlignmentError, seL4_CapInitThreadVspace,
        seL4_DeleteFirst, seL4_FailedLookup, seL4_IPCBufferSizeBits, seL4_IllegalOperation,
        seL4_InvalidArgument, seL4_InvalidCapability, seL4_PageBits, seL4_PageTableBits,
        seL4_RevokeFirst, seL4_TruncatedMessage, tcbBuffer, tcbVTable, RISCVASIDControlMakePool,
        RISCVASIDPoolAssign, RISCVGigaPageBits, RISCVInstructionAccessFault,
        RISCVInstructionPageFault, RISCVLoadAccessFault, RISCVLoadPageFault, RISCVMegaPageBits,
        RISCVPageBits, RISCVPageGetAddress, RISCVPageMap, RISCVPageTableMap, RISCVPageTableUnmap,
        RISCVPageUnmap, RISCVStoreAccessFault, RISCVStorePageFault, RISCV_4K_Page, RISCV_Giga_Page,
        RISCV_Mega_Page, ThreadStateRestart, VMKernelOnly, VMReadOnly, VMReadWrite,
        CONFIG_PT_LEVELS, IT_ASID, KERNEL_ELF_BASE, KERNEL_ELF_BASE_OFFSET, KERNEL_ELF_PADDR_BASE,
        PADDR_BASE, PPTR_BASE, PPTR_BASE_OFFSET, PPTR_TOP, PT_INDEX_BITS, USER_TOP,
    },
    kernel::boot::current_syscall_error,
    object::{
        cap::{cteInsert, ensureEmptySlot, ensureNoChildren, isFinalCapability},
        objecttype::{
            cap_asid_control_cap, cap_asid_pool_cap, cap_frame_cap, cap_get_capPtr,
            cap_get_capType, cap_page_table_cap, cap_untyped_cap,
        },
        structure_gen::{
            cap_asid_pool_cap_get_capASIDBase, cap_asid_pool_cap_get_capASIDPool,
            cap_asid_pool_cap_new, cap_frame_cap_get_capFBasePtr, cap_frame_cap_get_capFIsDevice,
            cap_frame_cap_get_capFMappedASID, cap_frame_cap_get_capFMappedAddress,
            cap_frame_cap_get_capFSize, cap_frame_cap_get_capFVMRights, cap_frame_cap_new,
            cap_frame_cap_set_capFMappedASID, cap_frame_cap_set_capFMappedAddress,
            cap_null_cap_new, cap_page_table_cap_get_capPTBasePtr,
            cap_page_table_cap_get_capPTIsMapped, cap_page_table_cap_get_capPTMappedASID,
            cap_page_table_cap_get_capPTMappedAddress, cap_page_table_cap_new,
            cap_page_table_cap_ptr_set_capPTIsMapped, cap_page_table_cap_set_capPTIsMapped,
            cap_page_table_cap_set_capPTMappedASID, cap_page_table_cap_set_capPTMappedAddress,
            cap_untyped_cap_get_capBlockSize, cap_untyped_cap_get_capIsDevice,
            cap_untyped_cap_get_capPtr, cap_untyped_cap_ptr_set_capFreeIndex,
            lookup_fault_invalid_root_new, lookup_fault_missing_capability_new,
            pte_ptr_get_execute, pte_ptr_get_ppn, pte_ptr_get_read, pte_ptr_get_valid,
            pte_ptr_get_write, seL4_Fault_VMFault_new,
        },
    },
    println,
    riscv::read_stval,
    structures::{
        asid_pool_t, cap_t, cte_t, exception_t, findVSpaceForASID_ret, lookupPTSlot_ret_t, pte_t,
        satp_t, seL4_CapRights_t, seL4_SlotRegion, tcb_t, v_region_t,
    },
    syscall::getSyscallArg,
    utils::MAX_FREE_INDEX,
    BIT, IS_ALIGNED, MASK, ROUND_DOWN,
};

use super::{
    boot::{
        clearMemory, current_extra_caps, current_fault, current_lookup_fault, it_alloc_paging,
        ndks_boot, provide_cap, rootserver, write_slot,
    },
    cspace::rust_lookupTargetSlot,
    thread::{getCSpace, ksCurThread, setMR, setRegister, setThreadState},
    transfermsg::{
        rightsFromWord, seL4_CapRights_get_capAllowRead, seL4_CapRights_get_capAllowWrite,
        seL4_MessageInfo_new, vmAttributesFromWord, vm_attributes_get_riscvExecuteNever,
        wordFromMEssageInfo,
    },
};

pub type pptr_t = usize;
pub type paddr_t = usize;
pub type vptr_t = usize;
pub type asid_t = usize;
pub type vm_rights_t = usize;

pub fn hwASIDFlush(asid: asid_t) {
    unsafe {
        asm!("sfence.vma x0, {0}",in(reg) asid);
    }
}

#[no_mangle]
#[link_section = ".page_table"]
static mut kernel_root_pageTable: [pte_t; BIT!(PT_INDEX_BITS)] =
    [pte_t { words: [0] }; BIT!(PT_INDEX_BITS)];

#[no_mangle]
#[link_section = ".page_table"]
static mut kernel_image_level2_pt: [pte_t; BIT!(PT_INDEX_BITS)] =
    [pte_t { words: [0] }; BIT!(PT_INDEX_BITS)];

#[no_mangle]
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
    let pte = pte_t {
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
    };
    pte
}

#[inline]
#[no_mangle]
pub fn pte_next(phys_addr: usize, is_leaf: bool) -> pte_t {
    let ppn = (phys_addr >> 12) as usize;

    let read = is_leaf as u8;
    let write = read;
    let exec = read;
    pte_new(
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
    )
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
    pte_ptr_get_valid(pte) != 0
        && !(pte_ptr_get_read(pte) != 0
            || pte_ptr_get_write(pte) != 0
            || pte_ptr_get_execute(pte) != 0)
}

#[no_mangle]
pub extern "C" fn lookupPTSlot(lvl1pt: *mut pte_t, vptr: vptr_t) -> lookupPTSlot_ret_t {
    let mut level = CONFIG_PT_LEVELS - 1;
    let mut pt: *mut pte_t = lvl1pt as *mut pte_t;
    let mut ret = lookupPTSlot_ret_t {
        ptBitsLeft: PT_INDEX_BITS * level + seL4_PageBits,
        ptSlot: unsafe {
            pt.add((vptr >> (PT_INDEX_BITS * level + seL4_PageBits)) & MASK!(PT_INDEX_BITS))
        },
    };
    while isPTEPageTable(ret.ptSlot) && level > 0 {
        level -= 1;
        ret.ptBitsLeft -= PT_INDEX_BITS;
        pt = getPPtrFromHWPTE(ret.ptSlot);
        ret.ptSlot = unsafe { pt.add((vptr >> ret.ptBitsLeft) & MASK!(PT_INDEX_BITS)) };
    }
    ret
}

#[inline]
pub fn getPPtrFromHWPTE(pte: *mut pte_t) -> *mut pte_t {
    paddr_to_pptr(pte_ptr_get_ppn(pte) << seL4_PageTableBits) as *mut pte_t
}

#[no_mangle]
pub extern "C" fn map_it_pt_cap(_vspace_cap: &cap_t, _pt_cap: &cap_t) {
    let vptr = cap_page_table_cap_get_capPTMappedAddress(_pt_cap);
    let lvl1pt = cap_get_capPtr(_vspace_cap) as *mut pte_t;
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
        )
        .words[0];
        sfence();
    }
}

pub fn create_it_pt_cap(vspace_cap: &cap_t, pptr: pptr_t, vptr: vptr_t, asid: usize) -> cap_t {
    let cap = cap_page_table_cap_new(asid, pptr, 1, vptr);
    map_it_pt_cap(vspace_cap, &cap);
    return cap;
}

#[no_mangle]
pub fn map_it_frame_cap(_vspace_cap: &cap_t, _frame_cap: &cap_t) {
    let vptr = cap_frame_cap_get_capFMappedAddress(_frame_cap);
    let lvl1pt = cap_get_capPtr(_vspace_cap) as *mut pte_t;
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
        )
        .words[0];
        sfence();
    }
}

pub fn rust_create_it_address_space(root_cnode_cap: &cap_t, it_v_reg: v_region_t) -> cap_t {
    unsafe {
        copyGlobalMappings(rootserver.vspace);
        let lvl1pt_cap = cap_page_table_cap_new(IT_ASID, rootserver.vspace, 1, rootserver.vspace);
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

#[no_mangle]
pub fn setVMRoot(thread: *mut tcb_t) {
    unsafe {
        let threadRoot = &(*getCSpace(thread as usize, tcbVTable)).cap;
        if cap_get_capType(threadRoot) != cap_page_table_cap {
            setVSpaceRoot(kpptr_to_paddr(kernel_root_pageTable.as_ptr() as usize), 0);
            return;
        }
        let lvl1pt = cap_page_table_cap_get_capPTBasePtr(threadRoot) as *mut pte_t;
        let asid = cap_page_table_cap_get_capPTMappedASID(threadRoot);
        let find_ret = findVSpaceForASID(asid);
        if unlikely(
            find_ret.status != exception_t::EXCEPTION_NONE || find_ret.vspace_root != lvl1pt,
        ) {
            setVSpaceRoot(kpptr_to_paddr(kernel_root_pageTable.as_ptr() as usize), 0);
            return;
        }
        setVSpaceRoot(pptr_to_paddr(lvl1pt as usize), asid);
    }
}

#[inline]
#[no_mangle]
pub fn pageBitsForSize(page_size: usize) -> usize {
    match page_size {
        RISCV_4K_Page => RISCVPageBits,
        RISCV_Mega_Page => RISCVMegaPageBits,
        RISCV_Giga_Page => RISCVGigaPageBits,
        _ => panic!("Invalid page size!"),
    }
}

#[no_mangle]
pub fn findVSpaceForASID(asid: asid_t) -> findVSpaceForASID_ret {
    let mut ret = findVSpaceForASID_ret {
        status: exception_t::EXCEPTION_FAULT,
        vspace_root: 0 as *mut pte_t,
    };
    let mut vspace_root: *mut pte_t = 0 as *mut pte_t;
    let mut poolPtr: *mut asid_pool_t = 0 as *mut asid_pool_t;
    unsafe {
        poolPtr = riscvKSASIDTable[asid >> asidLowBits];
    }
    if poolPtr as usize == 0 {
        unsafe {
            current_lookup_fault = lookup_fault_invalid_root_new();
        }
        ret.vspace_root = 0 as *mut pte_t;
        ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
        return ret;
    }
    unsafe {
        vspace_root = (*poolPtr).array[asid & MASK!(asidLowBits)];
    }
    if vspace_root as usize == 0 {
        unsafe {
            current_lookup_fault = lookup_fault_invalid_root_new();
        }
        ret.vspace_root = 0 as *mut pte_t;
        ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
        return ret;
    }
    ret.vspace_root = vspace_root;
    ret.status = exception_t::EXCEPTION_NONE;
    // vspace_root0xffffffc17fec1000
    return ret;
}

#[no_mangle]
pub extern "C" fn lookupIPCBuffer(isReceiver: bool, thread: *mut tcb_t) -> usize {
    unsafe {
        let w_bufferPtr = (*thread).tcbIPCBuffer;
        let bufferCap = &(*getCSpace(thread as usize, tcbBuffer)).cap;
        if cap_get_capType(bufferCap) != cap_frame_cap {
            return 0;
        }
        if cap_frame_cap_get_capFIsDevice(bufferCap) != 0 {
            return 0;
        }

        let vm_rights = cap_frame_cap_get_capFVMRights(bufferCap);
        if vm_rights == VMReadWrite || (!isReceiver && vm_rights == VMReadOnly) {
            let basePtr = cap_frame_cap_get_capFBasePtr(bufferCap);
            let pageBits = pageBitsForSize(cap_frame_cap_get_capFSize(bufferCap));
            return basePtr + (w_bufferPtr & MASK!(pageBits));
        }
        0
    }
}

#[no_mangle]
pub fn handleVMFault(_thread: *mut tcb_t, _type: usize) -> exception_t {
    let addr = read_stval();
    match _type {
        RISCVLoadPageFault | RISCVLoadAccessFault => {
            unsafe {
                current_fault = seL4_Fault_VMFault_new(addr, RISCVLoadAccessFault, false);
            }
            exception_t::EXCEPTION_FAULT
        }
        RISCVStorePageFault | RISCVStoreAccessFault => {
            unsafe {
                current_fault = seL4_Fault_VMFault_new(addr, RISCVStoreAccessFault, false);
            }
            exception_t::EXCEPTION_FAULT
        }
        RISCVInstructionAccessFault | RISCVInstructionPageFault => {
            unsafe {
                current_fault = seL4_Fault_VMFault_new(addr, RISCVInstructionAccessFault, true);
            }
            exception_t::EXCEPTION_FAULT
        }
        _ => panic!("Invalid VM fault type:{}", _type),
    }
}

#[no_mangle]
pub fn deleteASIDPool(asid_base: asid_t, pool: *mut asid_pool_t) {
    unsafe {
        if riscvKSASIDTable[asid_base >> asidLowBits] == pool {
            riscvKSASIDTable[asid_base >> asidLowBits] = 0 as *mut asid_pool_t;
            setVMRoot(ksCurThread);
        }
    }
}

#[no_mangle]
pub fn performASIDControlInvocation(
    frame: *mut usize,
    slot: *mut cte_t,
    parent: *mut cte_t,
    asid_base: usize,
) -> exception_t {
    unsafe {
        cap_untyped_cap_ptr_set_capFreeIndex(
            &mut (*parent).cap,
            MAX_FREE_INDEX(cap_untyped_cap_get_capBlockSize(&(*parent).cap)),
        );
    }
    clearMemory(frame as *mut u8, pageBitsForSize(RISCV_4K_Page));
    cteInsert(
        &cap_asid_pool_cap_new(asid_base, frame as usize),
        parent,
        slot,
    );
    assert!((asid_base & MASK!(asidLowBits)) == 0);
    unsafe {
        riscvKSASIDTable[asid_base >> asidLowBits] = frame as usize as *mut asid_pool_t;
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn performASIDPoolInvocation(
    asid: usize,
    poolPtr: *mut asid_pool_t,
    vspaceCapSlot: *mut cte_t,
) -> exception_t {
    let cap = unsafe { &mut (*vspaceCapSlot).cap };
    let regionBase = cap_page_table_cap_get_capPTBasePtr(cap) as *mut pte_t;
    cap_page_table_cap_set_capPTIsMapped(cap, 1);
    cap_page_table_cap_set_capPTMappedAddress(cap, 0);
    cap_page_table_cap_set_capPTMappedASID(cap, asid);

    copyGlobalMappings(regionBase as usize);

    unsafe {
        (*poolPtr).array[asid & MASK!(asidLowBits)] = regionBase;
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn deleteASID(asid: asid_t, vspace: *mut pte_t) {
    unsafe {
        let poolPtr = riscvKSASIDTable[asid >> asidLowBits];
        if poolPtr as usize != 0 && (*poolPtr).array[asid & MASK!(asidLowBits)] == vspace {
            hwASIDFlush(asid);
            (*poolPtr).array[asid & MASK!(asidLowBits)] = 0 as *mut pte_t;
            setVMRoot(ksCurThread as *mut tcb_t);
        }
    }
}

#[no_mangle]
pub fn unmapPageTable(asid: asid_t, vptr: vptr_t, target_pt: *mut pte_t) {
    let find_ret = findVSpaceForASID(asid);
    if find_ret.status != exception_t::EXCEPTION_NONE {
        return;
    }
    assert!(find_ret.vspace_root != target_pt);
    let mut pt = find_ret.vspace_root;
    let mut ptSlot: *mut pte_t = 0 as *mut pte_t;
    let mut i = 0;
    while i < CONFIG_PT_LEVELS - 1 && pt != target_pt {
        ptSlot = unsafe { pt.add(RISCV_GET_PT_INDEX(vptr, i)) };
        if unlikely(isPTEPageTable(ptSlot)) {
            return;
        }
        pt = getPPtrFromHWPTE(ptSlot);
        i += 1;
    }

    if pt != target_pt {
        return;
    }
    assert!(ptSlot as usize != 0);
    unsafe {
        let slot = ptSlot as *mut usize;
        *slot = pte_new(
            0, /* phy_address */
            0, /* sw */
            0, /* dirty (reserved non-leaf) */
            0, /* accessed (reserved non-leaf) */
            0, /* global */
            0, /* user (reserved non-leaf) */
            0, /* execute */
            0, /* write */
            0, /* read */
            0, /* valid */
        )
        .words[0];
        sfence();
    }
}

#[no_mangle]
pub fn pte_pte_invalid_new() -> pte_t {
    pte_t { words: [0] }
}

#[no_mangle]
pub fn unmapPage(page_size: usize, asid: asid_t, vptr: vptr_t, pptr: pptr_t) {
    let find_ret = findVSpaceForASID(asid);
    if find_ret.status != exception_t::EXCEPTION_NONE {
        return;
    }
    let lu_ret = lookupPTSlot(find_ret.vspace_root, vptr);

    if lu_ret.ptBitsLeft != pageBitsForSize(page_size) {
        return;
    }

    if !(pte_ptr_get_valid(lu_ret.ptSlot) != 0)
        || isPTEPageTable(lu_ret.ptSlot)
        || (pte_ptr_get_ppn(lu_ret.ptSlot) << seL4_PageBits) != pptr_to_paddr(pptr)
    {
        return;
    }
    unsafe {
        let slot = lu_ret.ptSlot as *mut usize;
        *slot = 0;
        sfence();
    }
}

#[no_mangle]
pub fn isValidVTableRoot(cap: &cap_t) -> bool {
    cap_get_capType(cap) == cap_page_table_cap && cap_page_table_cap_get_capPTIsMapped(cap) != 0
}

pub fn checkValidIPCBuffer(vptr: usize, cap: &cap_t) -> exception_t {
    if cap_get_capType(cap) != cap_frame_cap {
        println!("Requested IPC Buffer is not a frame cap.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    if cap_frame_cap_get_capFIsDevice(cap) != 0 {
        println!("Specifying a device frame as an IPC buffer is not permitted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    if !IS_ALIGNED!(vptr, seL4_IPCBufferSizeBits) {
        println!("Requested IPC Buffer location 0x%x is not aligned.");
        unsafe {
            current_syscall_error._type = seL4_AlignmentError;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn maskVMRights(vmrights: usize, rights: seL4_CapRights_t) -> usize {
    if vmrights == VMReadOnly && seL4_CapRights_get_capAllowRead(&rights) != 0 {
        return VMReadOnly;
    }
    if vmrights == VMReadWrite && seL4_CapRights_get_capAllowRead(&rights) != 0 {
        if seL4_CapRights_get_capAllowWrite(&rights) == 0 {
            return VMReadOnly;
        } else {
            return VMReadWrite;
        }
    }
    VMKernelOnly
}

pub fn RISCVGetWriteFromVMRights(vm_rights: usize) -> bool {
    return vm_rights == VMReadWrite;
}

pub fn RISCVGetReadFromVMRights(vm_rights: usize) -> bool {
    return vm_rights != VMKernelOnly;
}

#[no_mangle]
pub fn makeUserPTE(paddr: usize, executable: bool, vm_rights: usize) -> pte_t {
    let write = RISCVGetWriteFromVMRights(vm_rights);
    let read = RISCVGetReadFromVMRights(vm_rights);
    if !executable && !read && !write {
        return pte_pte_invalid_new();
    }
    pte_new(
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
#[no_mangle]
pub fn checkVPAlignment(sz: usize, w: usize) -> bool {
    w & MASK!(pageBitsForSize(sz)) == 0
}

#[no_mangle]
pub fn performPageInvocationUnmap(cap: &cap_t, ctSlot: *mut cte_t) -> exception_t {
    if cap_frame_cap_get_capFMappedASID(cap) != asidInvalid {
        unmapPage(
            cap_frame_cap_get_capFSize(cap),
            cap_frame_cap_get_capFMappedASID(cap),
            cap_frame_cap_get_capFMappedAddress(cap),
            cap_frame_cap_get_capFBasePtr(cap),
        );
    }

    unsafe {
        let slotCap = &mut (*ctSlot).cap;
        cap_frame_cap_set_capFMappedAddress(slotCap, 0);
        cap_frame_cap_set_capFMappedASID(slotCap, asidInvalid);
        (*ctSlot).cap = slotCap.clone();
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn updatePTE(pte: pte_t, base: *mut pte_t) -> exception_t {
    unsafe {
        *base = pte;
        sfence();
        forget(*base);
        exception_t::EXCEPTION_NONE
    }
}

#[no_mangle]
pub fn performPageInvocationMapPTE(
    cap: &cap_t,
    ctSlot: *mut cte_t,
    pte: pte_t,
    base: *mut pte_t,
) -> exception_t {
    unsafe {
        (*ctSlot).cap = cap.clone();
    }
    updatePTE(pte, base)
}

#[no_mangle]
pub fn performPageGetAddress(vbase_ptr: usize, call: bool) -> exception_t {
    unsafe {
        let thread = ksCurThread as *mut tcb_t;
        if call {
            let ipcBuffer = lookupIPCBuffer(true, thread as *mut tcb_t) as *mut usize;
            setRegister(thread as *mut tcb_t, badgeRegister, 0);
            let length = setMR(thread, ipcBuffer, 0, vbase_ptr);
            setRegister(
                thread,
                msgInfoRegister,
                wordFromMEssageInfo(seL4_MessageInfo_new(0, 0, 0, length)),
            );
        }
        setThreadState(thread, ThreadStateRestart);
        exception_t::EXCEPTION_NONE
    }
}

#[no_mangle]
pub fn performPageTableInvocationUnmap(cap: &cap_t, ctSlot: *mut cte_t) -> exception_t {
    if cap_page_table_cap_get_capPTIsMapped(cap) != 0 {
        let pt = cap_page_table_cap_get_capPTBasePtr(cap) as *mut pte_t;
        unmapPageTable(
            cap_page_table_cap_get_capPTMappedASID(cap),
            cap_page_table_cap_get_capPTMappedAddress(cap),
            pt,
        );
        clearMemory(pt as *mut u8, seL4_PageTableBits);
    }
    unsafe {
        cap_page_table_cap_ptr_set_capPTIsMapped(&mut (*ctSlot).cap, 0);
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn performPageTableInvocationMap(
    cap: &cap_t,
    ctSlot: *mut cte_t,
    pte: pte_t,
    ptSlot: *mut pte_t,
) -> exception_t {
    unsafe {
        (*ctSlot).cap = cap.clone();
        *ptSlot = pte;
        sfence();
        exception_t::EXCEPTION_NONE
    }
}

#[no_mangle]
pub fn decodeRISCVFrameInvocation(
    label: usize,
    length: usize,
    cte: *mut cte_t,
    cap: &mut cap_t,
    call: bool,
    buffer: *const usize,
) -> exception_t {
    match label {
        RISCVPageMap => unsafe {
            if length < 3 || current_extra_caps.excaprefs[0] as usize == 0 {
                println!("RISCVPageMap: Truncated message.");
                current_syscall_error._type = seL4_TruncatedMessage;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            let vaddr = getSyscallArg(0, buffer);
            let w_rightsMask = getSyscallArg(1, buffer);
            let attr = vmAttributesFromWord(getSyscallArg(2, buffer));
            let lvl1ptCap = &(*current_extra_caps.excaprefs[0]).cap;

            let frameSize = cap_frame_cap_get_capFSize(cap);
            let capVMRights = cap_frame_cap_get_capFVMRights(cap);

            if cap_get_capType(lvl1ptCap) != cap_page_table_cap
                || (cap_page_table_cap_get_capPTIsMapped(lvl1ptCap) == 0)
            {
                println!("RISCVPageMap: Bad PageTable cap.");
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 1;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let lvl1pt = cap_page_table_cap_get_capPTBasePtr(lvl1ptCap) as *mut pte_t;
            let asid = cap_page_table_cap_get_capPTMappedASID(lvl1ptCap);

            let find_ret = findVSpaceForASID(asid);
            if find_ret.status != exception_t::EXCEPTION_NONE {
                println!("RISCVPageMap: No PageTable for ASID");
                current_syscall_error._type = seL4_FailedLookup;
                current_syscall_error.failedLookupWasSource = false as usize;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            if find_ret.vspace_root != lvl1pt {
                println!("RISCVPageMap: ASID lookup failed");
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 1;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            let vtop = vaddr + BIT!(pageBitsForSize(frameSize)) - 1;

            if unlikely(vtop >= USER_TOP) {
                current_syscall_error._type = seL4_InvalidArgument;
                current_syscall_error.invalidCapNumber = 0;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            if unlikely(!checkVPAlignment(frameSize, vaddr)) {
                current_syscall_error._type = seL4_AlignmentError;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            let lu_ret = lookupPTSlot(lvl1pt, vaddr);

            if lu_ret.ptBitsLeft != pageBitsForSize(frameSize) {
                current_lookup_fault = lookup_fault_missing_capability_new(lu_ret.ptBitsLeft);
                current_syscall_error._type = seL4_FailedLookup;
                current_syscall_error.failedLookupWasSource = false as usize;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            let frame_asid = cap_frame_cap_get_capFMappedASID(cap);
            if frame_asid != asidInvalid {
                if frame_asid != asid {
                    println!("RISCVPageMap: Attempting to remap a frame that does not belong to the passed address space");
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 1;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }

                let mapped_vaddr = cap_frame_cap_get_capFMappedAddress(cap);
                if mapped_vaddr != vaddr {
                    println!("RISCVPageMap: attempting to map frame into multiple addresses");
                    current_syscall_error._type = seL4_InvalidArgument;
                    current_syscall_error.invalidArgumentNumber = 0;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }

                if isPTEPageTable(lu_ret.ptSlot) {
                    println!("RISCVPageMap: no mapping to remap.");
                    current_syscall_error._type = seL4_DeleteFirst;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            } else {
                if pte_ptr_get_valid(lu_ret.ptSlot) != 0 {
                    println!("Virtual address already mapped");
                    current_syscall_error._type = seL4_DeleteFirst;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            // let vmRights=m
            let vmRights = maskVMRights(capVMRights, rightsFromWord(w_rightsMask));
            let frame_paddr = pptr_to_paddr(cap_frame_cap_get_capFBasePtr(cap));
            cap_frame_cap_set_capFMappedASID(cap, asid);
            cap_frame_cap_set_capFMappedAddress(cap, vaddr);

            let executable = vm_attributes_get_riscvExecuteNever(attr) == 0;
            let pte = makeUserPTE(frame_paddr, executable, vmRights);
            setThreadState(ksCurThread, ThreadStateRestart);
            // println!(" res {:#x} {:#x} {:#x} {:#x} {:#x} {:#x}",cap.words[0],cap.words[1],cte as usize,pte.words[0],lu_ret.ptSlot as usize ,ksCurThread as usize);
            performPageInvocationMapPTE(cap, cte as *mut cte_t, pte, lu_ret.ptSlot as *mut pte_t)
        },
        RISCVPageUnmap => {
            unsafe {
                setThreadState(ksCurThread, ThreadStateRestart);
            }
            performPageInvocationUnmap(cap, cte)
        }
        RISCVPageGetAddress => {
            assert!(n_msgRegisters >= 1);
            unsafe {
                setThreadState(ksCurThread, ThreadStateRestart);
            }
            performPageGetAddress(cap_frame_cap_get_capFBasePtr(cap), call)
        }
        _ => {
            println!("invalid operation label:{}", label);
            unsafe {
                current_syscall_error._type = seL4_IllegalOperation;
            }
            exception_t::EXCEPTION_SYSCALL_ERROR
        }
    }
}

#[no_mangle]
pub fn decodeRISCVPageTableInvocation(
    label: usize,
    length: usize,
    cte: *mut cte_t,
    cap: &mut cap_t,
    buffer: *mut usize,
) -> exception_t {
    if label == RISCVPageTableUnmap {
        if !isFinalCapability(cte) {
            println!("RISCVPageTableUnmap: cannot unmap if more than once cap exists");
            unsafe {
                current_syscall_error._type = seL4_RevokeFirst;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        if cap_page_table_cap_get_capPTIsMapped(cap) != 0 {
            let asid = cap_page_table_cap_get_capPTMappedASID(cap);
            let find_ret = findVSpaceForASID(asid);
            let pte = cap_page_table_cap_get_capPTBasePtr(cap) as *mut pte_t;
            if find_ret.status == exception_t::EXCEPTION_NONE && find_ret.vspace_root == pte {
                println!("RISCVPageTableUnmap: cannot call unmap on top level PageTable");
                unsafe {
                    current_syscall_error._type = seL4_RevokeFirst;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
        }
        unsafe {
            setThreadState(ksCurThread, ThreadStateRestart);
        }
        return performPageTableInvocationUnmap(cap, cte);
    }

    if unlikely(label != RISCVPageTableMap) {
        println!("RISCVPageTable: Illegal Operation");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        if unlikely(length < 2 || current_extra_caps.excaprefs[0] as usize == 0) {
            println!("RISCVPageTable: truncated message");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    if unlikely(cap_page_table_cap_get_capPTIsMapped(cap) != 0) {
        println!("RISCVPageTable: PageTable is already mapped.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let vaddr = getSyscallArg(0, buffer);
    let lvl1ptCap = unsafe { &(*current_extra_caps.excaprefs[0]).cap };

    if cap_get_capType(lvl1ptCap) != cap_page_table_cap
        || cap_page_table_cap_get_capPTIsMapped(lvl1ptCap) == asidInvalid
    {
        println!("RISCVPageTableMap: Invalid top-level PageTable.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let lvl1pt = cap_page_table_cap_get_capPTBasePtr(lvl1ptCap) as *mut pte_t;
    let asid = cap_page_table_cap_get_capPTMappedASID(lvl1ptCap);

    if unlikely(vaddr >= USER_TOP) {
        println!("RISCVPageTableMap: Virtual address cannot be in kernel window.");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidCapNumber = 0;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let find_ret = findVSpaceForASID(asid);
    if find_ret.status != exception_t::EXCEPTION_NONE {
        println!("RISCVPageTableMap: ASID lookup failed");
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 0;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if find_ret.vspace_root != lvl1pt {
        println!("RISCVPageTableMap: ASID lookup failed");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let lu_ret = lookupPTSlot(lvl1pt, vaddr);
    if lu_ret.ptBitsLeft == seL4_PageBits || pte_ptr_get_valid(lu_ret.ptSlot) != 0 {
        println!("RISCVPageTableMap: All objects mapped at this address");
        unsafe {
            current_syscall_error._type = seL4_DeleteFirst;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let ptSlot = lu_ret.ptSlot;
    let paddr = pptr_to_paddr(cap_page_table_cap_get_capPTBasePtr(cap));
    let pte = pte_new(
        paddr >> seL4_PageBits,
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
    cap_page_table_cap_set_capPTIsMapped(cap, 1);
    cap_page_table_cap_set_capPTMappedASID(cap, asid);
    cap_page_table_cap_set_capPTMappedAddress(cap, vaddr & !MASK!(lu_ret.ptBitsLeft));
    unsafe {
        setThreadState(ksCurThread as *mut tcb_t, ThreadStateRestart);
    }
    performPageTableInvocationMap(cap, cte as *mut cte_t, pte, ptSlot)
}

#[no_mangle]
pub fn decodeRISCVMMUInvocation(
    label: usize,
    length: usize,
    _cptr: usize,
    cte: *mut cte_t,
    cap: &mut cap_t,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    match cap_get_capType(cap) {
        cap_page_table_cap => decodeRISCVPageTableInvocation(label, length, cte, cap, buffer),
        cap_frame_cap => decodeRISCVFrameInvocation(label, length, cte, cap, call, buffer),
        cap_asid_control_cap => {
            // println!("in cap_asid_control_cap");
            if label != RISCVASIDControlMakePool {
                unsafe {
                    current_syscall_error._type = seL4_IllegalOperation;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            unsafe {
                if unlikely(
                    length < 2
                        || current_extra_caps.excaprefs[0] as usize == 0
                        || current_extra_caps.excaprefs[1] as usize == 0,
                ) {
                    current_syscall_error._type = seL4_TruncatedMessage;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }

            let index = getSyscallArg(0, buffer);
            let depth = getSyscallArg(1, buffer);
            let parentSlot = unsafe { current_extra_caps.excaprefs[0] };
            let untyped = unsafe { &mut (*parentSlot).cap };
            let root = unsafe { &mut (*current_extra_caps.excaprefs[1]).cap };

            let mut i = 0;
            unsafe {
                while i < nASIDPools && riscvKSASIDTable[i] as usize != 0 {
                    i += 1;
                }
            }

            if i == nASIDPools {
                unsafe {
                    current_syscall_error._type = seL4_DeleteFirst;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            let asid_base = i << asidLowBits;

            if cap_get_capType(untyped) != cap_untyped_cap
                || cap_untyped_cap_get_capBlockSize(untyped) != seL4_ASIDPoolBits
                || cap_untyped_cap_get_capIsDevice(untyped) != 0
            {
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 1;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            let status = ensureNoChildren(parentSlot);

            if status != exception_t::EXCEPTION_NONE {
                return status;
            }

            let frame = cap_untyped_cap_get_capPtr(untyped) as *mut usize;

            let lu_ret = rust_lookupTargetSlot(root, index, depth);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                return lu_ret.status;
            }

            let destSlot = lu_ret.slot;

            let status1 = ensureEmptySlot(destSlot);
            if status1 != exception_t::EXCEPTION_NONE {
                return status1;
            }

            unsafe {
                setThreadState(ksCurThread, ThreadStateRestart);
            }
            performASIDControlInvocation(frame, destSlot, parentSlot, asid_base)
        }

        cap_asid_pool_cap => {
            // println!("in cap_asid_pool_cap");
            if label != RISCVASIDPoolAssign {
                unsafe {
                    current_syscall_error._type = seL4_IllegalOperation;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            unsafe {
                if unlikely(current_extra_caps.excaprefs[0] as usize == 0) {
                    current_syscall_error._type = seL4_TruncatedMessage;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }

            let vspaceCapSlot = unsafe { current_extra_caps.excaprefs[0] };
            let vspaceCap = unsafe { &mut (*vspaceCapSlot).cap };

            if unlikely(
                cap_get_capType(vspaceCap) != cap_page_table_cap
                    || cap_page_table_cap_get_capPTIsMapped(vspaceCap) != 0,
            ) {
                unsafe {
                    println!("RISCVASIDPool: Invalid vspace root.");
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 1;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            let pool =
                unsafe { riscvKSASIDTable[cap_asid_pool_cap_get_capASIDBase(cap) >> asidLowBits] };

            if pool as usize == 0 {
                unsafe {
                    current_syscall_error._type = seL4_FailedLookup;
                    current_syscall_error.failedLookupWasSource = 0;
                    current_lookup_fault = lookup_fault_invalid_root_new();
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            if pool as usize != cap_asid_pool_cap_get_capASIDPool(cap) {
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }

            let mut asid = cap_asid_pool_cap_get_capASIDBase(cap);
            let mut i = 0;
            unsafe {
                while i < BIT!(asidLowBits) && (asid + i == 0 || (*pool).array[i] as usize != 0) {
                    i += 1;
                }
            }

            if i == BIT!(asidLowBits) {
                unsafe {
                    current_syscall_error._type = seL4_DeleteFirst;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            asid += i;

            unsafe {
                setThreadState(ksCurThread, ThreadStateRestart);
                performASIDPoolInvocation(asid, pool, vspaceCapSlot)
            }
        }
        _ => {
            panic!("Invalid arch cap type");
        }
    }
}
