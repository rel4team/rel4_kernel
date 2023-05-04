extern crate core;
use core::mem::{forget, size_of};
use riscv::register::{stvec, utvec::TrapMode};

use crate::{
    config::{
        asidLowBits, irqInvalid, ksDomScheduleLength, maxIRQ, seL4_ASIDPoolBits,
        seL4_CapASIDControl, seL4_CapBootInfoFrame, seL4_CapDomain, seL4_CapIRQControl,
        seL4_CapInitThreadASIDPool, seL4_CapInitThreadCNode, seL4_CapInitThreadIPCBuffer,
        seL4_CapInitThreadTCB, seL4_CapInitThreadVspace, seL4_MaxPrio, seL4_MaxUntypedBits,
        seL4_MinUntypedBits, seL4_MsgMaxExtraCaps, seL4_NumInitialCaps, seL4_PageBits,
        seL4_PageTableBits, seL4_SlotBits, seL4_TCBBits, seL4_VSpaceBits, seL4_WordBits, tcbBuffer,
        tcbCTable, tcbVTable, wordBits, IRQInactive, IRQTimer, RISCVMegaPageBits, RISCVPageBits,
        ThreadStateRunning, VMReadWrite, BI_FRAME_SIZE_BITS, CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS,
        CONFIG_MAX_NUM_NODES, CONFIG_NUM_DOMAINS, CONFIG_PADDR_USER_DEVICE_TOP, CONFIG_PT_LEVELS,
        CONFIG_ROOT_CNODE_SIZE_BITS, CONFIG_TIME_SLICE, IT_ASID, KERNEL_ELF_BASE, KERNEL_TIMER_IRQ,
        MAX_NUM_FREEMEM_REG, MAX_NUM_RESV_REG, NUM_RESERVED_REGIONS, PADDR_TOP, PAGE_BITS,
        PPTR_BASE, PPTR_TOP, PT_INDEX_BITS, RESET_CYCLES, SEL4_BOOTINFO_HEADER_FDT,
        SEL4_BOOTINFO_HEADER_PADDING, SIE_SEIE, SIE_STIE, TCB_OFFSET, USER_TOP,
    },
    kernel::vspace::{
        activate_kernel_vspace, rust_create_it_address_space, rust_map_kernel_window,
        write_it_asid_pool,
    },
    object::{
        cap::cteInsert,
        cnode::setupReplyMaster,
        interrupt::{setIRQState, set_sie_mask},
        objecttype::{cap_get_capPtr, cap_get_capType, cap_null_cap, deriveCap},
        structure_gen::{
            cap_asid_control_cap_new, cap_asid_pool_cap_new, cap_cnode_cap_new, cap_domain_cap_new,
            cap_frame_cap_new, cap_irq_control_cap_new, cap_thread_cap_new, cap_untyped_cap_new,
            mdb_node_set_mdbFirstBadged, mdb_node_set_mdbRevocable,
        },
    },
    println,
    sbi::{get_time, set_timer},
    structures::{
        cap_t, create_frames_of_region_ret_t, cte_t, dschedule_t, exception_t, extra_caps_t,
        lookup_fault_t, mdb_node_t, ndks_boot_t, p_region_t, region_t, rootserver_mem_t,
        seL4_BootInfo, seL4_BootInfoHeader, seL4_Fault_t, seL4_IPCBuffer, seL4_SlotPos,
        seL4_SlotRegion, seL4_UntypedDesc, syscall_error_t, tcb_t, v_region_t,
    },
    utils::MAX_FREE_INDEX,
    BIT, IS_ALIGNED, MASK, ROUND_DOWN, ROUND_UP,
};

use super::{
    thread::{
        capRegister, configureIdleThread, getCSpace, ksCurDomain, ksCurThread, ksDomScheduleIdx,
        ksDomainTime, ksIdleThread, ksIdleThreadTCB, ksSchedulerAction, setNextPC, setRegister,
        setThreadState, Arch_initContext,
    },
    vspace::{
        kpptr_to_paddr, map_it_frame_cap, paddr_to_pptr, pptr_to_paddr,
        rust_create_unmapped_it_frame_cap,
    },
};

#[link(name = "kernel_all.c")]
extern "C" {
    fn init_plat();
    fn tcbDebugAppend(action: *mut tcb_t);
}

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut active_irq: [usize; 1] = [0; 1];

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut current_lookup_fault: lookup_fault_t = lookup_fault_t { words: [0; 2] };

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut current_fault: seL4_Fault_t = seL4_Fault_t { words: [0; 2] };

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut current_syscall_error: syscall_error_t = syscall_error_t {
    invalidArgumentNumber: 0,
    invalidCapNumber: 0,
    rangeErrorMax: 0,
    rangeErrorMin: 0,
    memoryLeft: 0,
    failedLookupWasSource: 0,
    _type: 0,
};

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut ksWorkUnitsCompleted: usize = 0;

#[link_section = ".boot.bss"]
static mut res_reg: [region_t; NUM_RESERVED_REGIONS] =
    [region_t { start: 0, end: 0 }; NUM_RESERVED_REGIONS];

#[link_section = ".boot.bss"]
static mut avail_reg: [region_t; MAX_NUM_FREEMEM_REG] =
    [region_t { start: 0, end: 0 }; MAX_NUM_FREEMEM_REG];

#[link_section = ".boot.bss"]
static mut avail_p_regs_addr: usize = 0;

#[link_section = ".boot.bss"]
static mut avail_p_regs_size: usize = 0;

#[no_mangle]
#[link_section = ".boot.bss"]
static mut rootserver_mem: region_t = region_t { start: 0, end: 0 };
#[link_section = ".boot.bss"]
pub static mut ksDomSchedule: [dschedule_t; ksDomScheduleLength] = [dschedule_t {
    domain: 0,
    length: 60,
}; ksDomScheduleLength];

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut ndks_boot: ndks_boot_t = ndks_boot_t {
    reserved: [p_region_t { start: 0, end: 0 }; MAX_NUM_RESV_REG],
    resv_count: 0,
    freemem: [region_t { start: 0, end: 0 }; MAX_NUM_FREEMEM_REG],
    bi_frame: 0 as *mut seL4_BootInfo,
    slot_pos_cur: seL4_NumInitialCaps,
};

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut rootserver: rootserver_mem_t = rootserver_mem_t {
    cnode: 0,
    vspace: 0,
    asid_pool: 0,
    ipc_buf: 0,
    boot_info: 0,
    extra_bi: 0,
    tcb: 0,
    paging: region_t {
        start: (0),
        end: (0),
    },
};

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut current_extra_caps: extra_caps_t = extra_caps_t {
    excaprefs: [0 as *mut cte_t; seL4_MsgMaxExtraCaps],
};

pub extern "C" fn initTimer() {
    set_timer(get_time() + RESET_CYCLES);
}

#[no_mangle]
pub extern "C" fn init_cpu() {
    activate_kernel_vspace();
    extern "C" {
        fn trap_entry();
    }
    unsafe {
        stvec::write(trap_entry as usize, TrapMode::Direct);
    }
    set_sie_mask(BIT!(SIE_SEIE) | BIT!(SIE_STIE));
    initTimer();
}

#[no_mangle]
pub extern "C" fn initIRQController(arr: *mut i32, size: usize) {
    unsafe {
        let data = core::slice::from_raw_parts_mut(arr, size);
        for i in 0..size {
            data[i] = 0;
        }
    }
}

pub extern "C" fn calculate_extra_bi_size_bits(size: usize) -> usize {
    if size == 0 {
        return 0;
    }

    let clzl_ret = ROUND_UP!(size, seL4_PageBits).leading_zeros() as usize;
    let mut msb = seL4_WordBits - 1 - clzl_ret;
    if size > BIT!(msb) {
        msb += 1;
    }
    return msb;
}

#[inline]
pub fn pptr_to_paddr_reg(reg: region_t) -> p_region_t {
    p_region_t {
        start: pptr_to_paddr(reg.start),
        end: pptr_to_paddr(reg.end),
    }
}

#[inline]
pub fn paddr_to_pptr_reg(reg: &p_region_t) -> region_t {
    region_t {
        start: paddr_to_pptr(reg.start),
        end: paddr_to_pptr(reg.end),
    }
}

#[no_mangle]
pub fn pRegsToR(ptr: *const usize, size: usize) {
    unsafe {
        avail_p_regs_addr = ptr as usize;
        avail_p_regs_size = size;
        // println!("{:#x} {:#x}", avail_p_regs_addr, avail_p_regs_size);
    }
}

pub fn rust_arch_init_freemem(
    ui_reg: region_t,
    dtb_p_reg: p_region_t,
    it_v_reg: v_region_t,
    extra_bi_size_bits: usize,
) -> bool {
    extern "C" {
        fn ki_end();
    }
    unsafe {
        res_reg[0].start = paddr_to_pptr(kpptr_to_paddr(KERNEL_ELF_BASE));
        res_reg[0].end = paddr_to_pptr(kpptr_to_paddr(ki_end as usize));
    }
    let mut index = 1;

    if dtb_p_reg.start != 0 {
        if index >= NUM_RESERVED_REGIONS {
            println!("ERROR: no slot to add DTB to reserved regions\n");
            return false;
        }
        unsafe {
            res_reg[index] = paddr_to_pptr_reg(&dtb_p_reg);
            index += 1;
        }
    }
    if index >= NUM_RESERVED_REGIONS {
        println!("ERROR: no slot to add user image to reserved regions\n");
        return false;
    }
    unsafe {
        res_reg[index] = ui_reg;
        index += 1;
        rust_init_freemem(
            avail_p_regs_size,
            avail_p_regs_addr,
            index,
            res_reg.clone(),
            it_v_reg,
            extra_bi_size_bits,
        )
    }
}

pub extern "C" fn check_available_memory(n_available: usize, available: usize) -> bool {
    if n_available == 0 {
        println!("ERROR: no memory regions available");
        return false;
    }
    println!("available phys memory regions: {:#x}", n_available);
    let mut last: p_region_t = unsafe { (*(available as *const p_region_t).add(0)).clone() };
    for i in 0..n_available {
        let r: p_region_t;
        unsafe {
            r = (*(available as *const p_region_t).add(i)).clone();
        }
        println!(" [{:#x}..{:#x}]", r.start, r.end);

        if r.start > r.end {
            println!("ERROR: memory region {} has start > end", i);
            return false;
        }

        if r.start == r.end {
            println!("ERROR: memory region {} empty", i);
            return false;
        }
        if i > 0 && r.start < last.end {
            println!("ERROR: memory region {} in wrong order", i);
        }
        last = r.clone();
    }
    return true;
}
pub fn check_reserved_memory(
    n_reserved: usize,
    reserved: [region_t; NUM_RESERVED_REGIONS],
) -> bool {
    println!("reserved virt address space regions: {}", n_reserved);
    let mut last: region_t = reserved[0].clone();
    for i in 0..n_reserved {
        let r: region_t;
        r = reserved[i].clone();
        println!("  [{:#x}..{:#x}]", r.start, r.end);
        if r.start > r.end {
            println!("ERROR: reserved region {} has start > end\n", i);
            return false;
        }

        if i > 0 && r.start < last.end {
            println!("ERROR: reserved region {} in wrong order", i);
            return false;
        }
        last = r.clone();
    }
    true
}

pub extern "C" fn ceiling_kernel_window(mut p: usize) -> usize {
    if pptr_to_paddr(p) > PADDR_TOP {
        p = PPTR_TOP;
    }
    p
}

#[inline]
pub fn merge_regions() {
    unsafe {
        let mut i = 1;
        while i < ndks_boot.resv_count {
            if ndks_boot.reserved[i - 1].end == ndks_boot.reserved[i].start {
                ndks_boot.reserved[i - 1].end = ndks_boot.reserved[i].end;
                let mut j = i + 1;
                while j < ndks_boot.resv_count {
                    ndks_boot.reserved[j - 1] = ndks_boot.reserved[j];
                    j += 1;
                }
                ndks_boot.resv_count -= 1;
            } else {
                i += 1;
            }
        }
    }
}

#[inline]
pub fn is_reg_empty(reg: &region_t) -> bool {
    reg.start == reg.end
}

pub fn insert_region(reg: region_t) -> bool {
    unsafe {
        assert!(reg.start <= reg.end);

        if is_reg_empty(&reg) {
            return true;
        }
        let mut i = 0;
        while i < ndks_boot.freemem.len() {
            if is_reg_empty(&ndks_boot.freemem[i]) {
                reserve_region(pptr_to_paddr_reg(reg));
                ndks_boot.freemem[i] = reg;
                return true;
            }
            i += 1;
        }
    }
    println!(
        "no free memory slot left for [{}..{}],
     consider increasing MAX_NUM_FREEMEM_REG (%{})\n",
        reg.start, reg.end, MAX_NUM_FREEMEM_REG
    );
    assert!(false);
    return false;
}

pub fn reserve_region(reg: p_region_t) -> bool {
    unsafe {
        assert!(reg.start <= reg.end);
        if reg.start == reg.end {
            return true;
        }

        let mut i = 0;
        while i < ndks_boot.resv_count {
            if ndks_boot.reserved[i].start == reg.end {
                ndks_boot.reserved[i].start = reg.start;
                merge_regions();
                return true;
            }
            if ndks_boot.reserved[i].end == reg.start {
                ndks_boot.reserved[i].end = reg.end;
                merge_regions();
                return true;
            }
            if ndks_boot.reserved[i].start > reg.end {
                if ndks_boot.resv_count + 1 >= MAX_NUM_RESV_REG {
                    println!("Can't mark region {:#x}-{:#x} as reserved, try increasing MAX_NUM_RESV_REG (currently {})\n",reg.start,reg.end,MAX_NUM_RESV_REG);
                    return false;
                }
                let mut j = ndks_boot.resv_count;
                while j > i {
                    ndks_boot.reserved[j] = ndks_boot.reserved[j - 1];
                    j -= 1;
                }
                ndks_boot.reserved[i] = reg;
                ndks_boot.resv_count += 1;
                return true;
            }
            i += 1;
        }
        if i + 1 == MAX_NUM_RESV_REG {
            println!("Can't mark region 0x{}-0x{} as reserved, try increasing MAX_NUM_RESV_REG (currently {})\n",reg.start,reg.end,MAX_NUM_RESV_REG);
            return false;
        }
        ndks_boot.reserved[i] = reg;
        ndks_boot.resv_count += 1;
        return true;
    }
}

#[inline]
pub fn get_n_paging(v_reg: v_region_t, bits: usize) -> usize {
    let start = ROUND_DOWN!(v_reg.start, bits);
    let end = ROUND_UP!(v_reg.end, bits);
    (end - start) / BIT!(bits)
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

pub fn arch_get_n_paging(it_v_reg: v_region_t) -> usize {
    let mut n: usize = 0;
    for i in 0..CONFIG_PT_LEVELS - 1 {
        n += get_n_paging(it_v_reg, RISCV_GET_LVL_PGSIZE_BITS(i));
    }
    return n;
}

pub fn calculate_rootserver_size(it_v_reg: v_region_t, extra_bi_size_bits: usize) -> usize {
    let mut size = BIT!(CONFIG_ROOT_CNODE_SIZE_BITS + seL4_SlotBits);
    size += BIT!(seL4_TCBBits);
    size += BIT!(seL4_PageBits);
    size += BIT!(BI_FRAME_SIZE_BITS);
    size += BIT!(seL4_ASIDPoolBits);
    size += if extra_bi_size_bits > 0 {
        BIT!(extra_bi_size_bits)
    } else {
        0
    };
    size += BIT!(seL4_VSpaceBits);
    return size + arch_get_n_paging(it_v_reg) * BIT!(seL4_PageTableBits);
}

pub fn rootserver_max_size_bits(extra_bi_size_bits: usize) -> usize {
    let cnode_size_bits = CONFIG_ROOT_CNODE_SIZE_BITS + seL4_SlotBits;
    let maxx = if cnode_size_bits > seL4_VSpaceBits {
        cnode_size_bits
    } else {
        seL4_VSpaceBits
    };
    if maxx > extra_bi_size_bits {
        maxx
    } else {
        extra_bi_size_bits
    }
}

pub fn alloc_rootserver_obj(size_bits: usize, n: usize) -> usize {
    unsafe {
        let allocated = rootserver_mem.start;
        assert!(allocated % BIT!(size_bits) == 0);
        rootserver_mem.start += n * BIT!(size_bits);
        assert!(rootserver_mem.start <= rootserver_mem.end);
        allocated
    }
}

pub fn maybe_alloc_extra_bi(cmp_size_bits: usize, extra_bi_size_bits: usize) {
    unsafe {
        if extra_bi_size_bits >= cmp_size_bits && rootserver.extra_bi == 0 {
            rootserver.extra_bi = alloc_rootserver_obj(extra_bi_size_bits, 1);
        }
    }
}

pub fn create_rootserver_objects(start: usize, it_v_reg: v_region_t, extra_bi_size_bits: usize) {
    unsafe {
        let cnode_size_bits = CONFIG_ROOT_CNODE_SIZE_BITS + seL4_SlotBits;
        let max = rootserver_max_size_bits(extra_bi_size_bits);

        let size = calculate_rootserver_size(it_v_reg, extra_bi_size_bits);
        rootserver_mem.start = start;
        rootserver_mem.end = start + size;
        maybe_alloc_extra_bi(max, extra_bi_size_bits);

        rootserver.cnode = alloc_rootserver_obj(cnode_size_bits, 1);
        maybe_alloc_extra_bi(seL4_VSpaceBits, extra_bi_size_bits);
        rootserver.vspace = alloc_rootserver_obj(seL4_VSpaceBits, 1);

        maybe_alloc_extra_bi(seL4_PageBits, extra_bi_size_bits);
        rootserver.asid_pool = alloc_rootserver_obj(seL4_ASIDPoolBits, 1);
        rootserver.ipc_buf = alloc_rootserver_obj(seL4_PageBits, 1);
        rootserver.boot_info = alloc_rootserver_obj(BI_FRAME_SIZE_BITS, 1);

        let n = arch_get_n_paging(it_v_reg);
        rootserver.paging.start = alloc_rootserver_obj(seL4_PageTableBits, n);
        rootserver.paging.end = rootserver.paging.start + n * BIT!(seL4_PageTableBits);
        rootserver.tcb = alloc_rootserver_obj(seL4_TCBBits, 1);

        assert!(rootserver_mem.start == rootserver_mem.end);
    }
}

pub fn init_irqs(root_cnode_cap: &cap_t) {
    for i in 0..maxIRQ + 1 {
        if i != irqInvalid {
            setIRQState(IRQInactive, i);
        }
    }
    setIRQState(IRQTimer, KERNEL_TIMER_IRQ);
    let ptr = cap_get_capPtr(&root_cnode_cap) as *mut cte_t;
    unsafe {
        write_slot(ptr.add(seL4_CapIRQControl), cap_irq_control_cap_new());
    }
}

pub fn rust_init_freemem(
    n_available: usize,
    available: usize,
    n_reserved: usize,
    reserved: [region_t; NUM_RESERVED_REGIONS],
    it_v_reg: v_region_t,
    extra_bi_size_bits: usize,
) -> bool {
    if !check_available_memory(n_available, available)
        || !check_reserved_memory(n_reserved, reserved.clone())
    {
        return false;
    }
    unsafe {
        for i in 0..ndks_boot.freemem.len() {
            ndks_boot.freemem[i] = region_t { start: 0, end: 0 };
        }

        for i in 0..n_available {
            let ptr = (*(available as *mut p_region_t).add(i)).clone();

            avail_reg[i] = paddr_to_pptr_reg(&ptr);
            avail_reg[i].end = ceiling_kernel_window(avail_reg[i].end);
            avail_reg[i].start = ceiling_kernel_window(avail_reg[i].start);
        }

        let mut a = 0;
        let mut r = 0;

        while a < n_available && r < n_reserved {
            if reserved[r].start == reserved[r].end {
                /* reserved region is empty - skip it */
                r += 1;
            } else if avail_reg[a].start >= avail_reg[a].end {
                /* skip the entire region - it's empty now after trimming */
                a += 1;
            } else if reserved[r].end <= avail_reg[a].start {
                /* the reserved region is below the available region - skip it */
                reserve_region(pptr_to_paddr_reg(reserved[r]));
                r += 1;
            } else if reserved[r].start >= avail_reg[a].end {
                /* the reserved region is above the available region - take the whole thing */
                insert_region(avail_reg[a]);
                a += 1;
            } else {
                if reserved[r].start <= avail_reg[a].start {
                    avail_reg[a].start = if avail_reg[a].end < reserved[r].end {
                        avail_reg[a].end
                    } else {
                        reserved[r].end
                    };
                    reserve_region(pptr_to_paddr_reg(reserved[r]));
                    r += 1;
                } else {
                    assert!(reserved[r].start < avail_reg[a].end);
                    /* take the first chunk of the available region and move
                     * the start to the end of the reserved region */
                    let mut m = avail_reg[a];
                    m.end = reserved[r].start;
                    insert_region(m);
                    if avail_reg[a].end > reserved[r].end {
                        avail_reg[a].start = reserved[r].end;
                        reserve_region(pptr_to_paddr_reg(reserved[r]));
                        r += 1;
                    } else {
                        a += 1;
                    }
                }
            }
        }

        while r < n_reserved {
            if reserved[r].start < reserved[r].end {
                reserve_region(pptr_to_paddr_reg(reserved[r]));
            }
            r += 1;
        }
        while a < n_available {
            if avail_reg[a].start < avail_reg[a].end {
                insert_region(avail_reg[a]);
            }
            a += 1;
        }
        let mut i = ndks_boot.freemem.len() - 1;
        if !is_reg_empty(&ndks_boot.freemem[i]) {
            println!(
                "ERROR: insufficient MAX_NUM_FREEMEM_REG {}\n",
                MAX_NUM_FREEMEM_REG
            );
            return false;
        }

        /* skip any empty regions */
        while i >= 0 && is_reg_empty(&ndks_boot.freemem[i]) {
            i -= 1;
        }

        /* try to grab the last available p region to create the root server objects
         * from. If possible, retain any left over memory as an extra p region */
        let size = calculate_rootserver_size(it_v_reg, extra_bi_size_bits);
        let max = rootserver_max_size_bits(extra_bi_size_bits);

        while i >= 0 && i < ndks_boot.freemem.len() {
            /* Invariant: both i and (i + 1) are valid indices in ndks_boot.freemem. */
            assert!(i < (ndks_boot.freemem.len() - 1));
            /* Invariant; the region at index i is the current candidate.
             * Invariant: regions 0 up to (i - 1), if any, are additional candidates.
             * Invariant: region (i + 1) is empty. */
            assert!(is_reg_empty(&ndks_boot.freemem[i + 1]));

            let empty_index = i + 1;
            let unaligned_start = ndks_boot.freemem[i].end - size;
            let start = ROUND_DOWN!(unaligned_start, max);

            /* if unaligned_start didn't underflow, and start fits in the region,
             * then we've found a region that fits the root server objects. */
            if unaligned_start <= ndks_boot.freemem[i].end && start >= ndks_boot.freemem[i].start {
                create_rootserver_objects(start, it_v_reg, extra_bi_size_bits);
                ndks_boot.freemem[empty_index] = region_t {
                    start: start + size,
                    end: ndks_boot.freemem[i].end,
                };
                ndks_boot.freemem[i].end = start;
                return true;
            }
            /* Region i isn't big enough, so shuffle it up to slot (i + 1),
             * which we know is unused. */
            ndks_boot.freemem[empty_index] = ndks_boot.freemem[i];
            ndks_boot.freemem[i] = region_t { start: 0, end: 0 };
            i -= 1;
        }
        println!("ERROR: no free memory region is big enough for root server objects, need size/alignment of 2^{}\n", max);
    }

    false
}

pub fn write_slot(ptr: *mut cte_t, cap: cap_t) {
    unsafe {
        (*ptr).cap = cap;
        (*ptr).cteMDBNode = mdb_node_t::default();

        mdb_node_set_mdbRevocable(&mut (*ptr).cteMDBNode, 1);
        mdb_node_set_mdbFirstBadged(&mut (*ptr).cteMDBNode, 1);
        forget(*ptr);
    }
}

pub fn create_root_cnode() -> cap_t {
    unsafe {
        let cap = cap_cnode_cap_new(
            CONFIG_ROOT_CNODE_SIZE_BITS,
            wordBits - CONFIG_ROOT_CNODE_SIZE_BITS,
            0,
            rootserver.cnode,
        );
        let ptr = rootserver.cnode as *mut cte_t;
        write_slot(ptr.add(seL4_CapInitThreadCNode), cap.clone());
        cap
    }
}

pub extern "C" fn create_domain_cap(root_cnode_cap: &cap_t) {
    assert!(ksDomScheduleLength > 0);
    for i in 0..ksDomScheduleLength {
        unsafe {
            assert!(ksDomSchedule[i].domain < CONFIG_NUM_DOMAINS);
            assert!(ksDomSchedule[i].length > 0);
        }
    }
    let cap = cap_domain_cap_new();
    unsafe {
        let pos = cap_get_capPtr(root_cnode_cap) as *mut cte_t;
        write_slot(pos.add(seL4_CapDomain), cap);
    }
}

#[inline]
pub fn clearMemory(ptr: *mut u8, bits: usize) {
    unsafe {
        core::slice::from_raw_parts_mut(ptr, BIT!(bits)).fill(0);
    }
}

#[no_mangle]
pub fn rust_populate_bi_frame(
    node_id: usize,
    num_nodes: usize,
    ipcbuf_vptr: usize,
    extra_bi_size: usize,
) {
    unsafe {
        clearMemory(rootserver.boot_info as *mut u8, BI_FRAME_SIZE_BITS);
        if extra_bi_size != 0 {
            clearMemory(
                rootserver.extra_bi as *mut u8,
                calculate_extra_bi_size_bits(extra_bi_size),
            );
        }
        let bi = &mut *(rootserver.boot_info as *mut seL4_BootInfo);
        bi.nodeID = node_id;
        bi.numNodes = num_nodes;
        bi.numIOPTLevels = 0;
        bi.ipcBuffer = ipcbuf_vptr as *mut seL4_IPCBuffer;
        bi.initThreadCNodeSizeBits = CONFIG_ROOT_CNODE_SIZE_BITS;
        bi.initThreadDomain = ksDomSchedule[ksDomScheduleIdx].domain;
        bi.extraLen = extra_bi_size;

        ndks_boot.bi_frame = bi as *const seL4_BootInfo as *mut seL4_BootInfo;
        ndks_boot.slot_pos_cur = seL4_NumInitialCaps;

        forget(bi);
    }
}

#[inline]
pub fn it_alloc_paging() -> usize {
    unsafe {
        let allocated = rootserver.paging.start;
        rootserver.paging.start += BIT!(seL4_PageTableBits);
        assert!(rootserver.paging.start <= rootserver.paging.end);
        allocated
    }
}

pub fn rust_create_mapped_it_frame_cap(
    pd_cap: &cap_t,
    pptr: usize,
    vptr: usize,
    asid: usize,
    use_large: bool,
    _exec: bool,
) -> cap_t {
    let frame_size: usize;
    if use_large {
        frame_size = RISCVMegaPageBits;
    } else {
        frame_size = RISCVPageBits;
    }
    let cap = cap_frame_cap_new(asid, pptr, frame_size, VMReadWrite, 0, vptr);
    map_it_frame_cap(pd_cap, &cap);
    cap
}

pub fn provide_cap(root_cnode_cap: &cap_t, cap: cap_t) -> bool {
    unsafe {
        if ndks_boot.slot_pos_cur >= BIT!(CONFIG_ROOT_CNODE_SIZE_BITS) {
            println!(
                "ERROR: can't add another cap, all {} (=2^CONFIG_ROOT_CNODE_SIZE_BITS) slots used",
                BIT!(CONFIG_ROOT_CNODE_SIZE_BITS)
            );
            return false;
        }
        let ptr = cap_get_capPtr(root_cnode_cap) as *mut cte_t;
        write_slot(ptr.add(ndks_boot.slot_pos_cur), cap);
        ndks_boot.slot_pos_cur += 1;
        return true;
    }
}

pub fn create_bi_frame_cap(root_cnode_cap: &cap_t, pd_cap: &cap_t, vptr: usize) {
    unsafe {
        let cap = rust_create_mapped_it_frame_cap(
            pd_cap,
            rootserver.boot_info,
            vptr,
            IT_ASID,
            false,
            false,
        );
        let ptr = cap_get_capPtr(root_cnode_cap) as *mut cte_t;
        write_slot(ptr.add(seL4_CapBootInfoFrame), cap);
    }
}

pub fn rust_create_frames_of_region(
    root_cnode_cap: &cap_t,
    pd_cap: &cap_t,
    reg: region_t,
    do_map: bool,
    pv_offset: isize,
) -> create_frames_of_region_ret_t {
    let slot_pos_before = unsafe { ndks_boot.slot_pos_cur };
    let mut f = reg.start;
    let mut frame_cap: cap_t;
    while f < reg.end {
        if do_map {
            frame_cap = rust_create_mapped_it_frame_cap(
                pd_cap,
                f,
                pptr_to_paddr((f as isize - pv_offset) as usize),
                IT_ASID,
                false,
                true,
            );
        } else {
            frame_cap = rust_create_unmapped_it_frame_cap(f, false);
        }

        if !provide_cap(root_cnode_cap, frame_cap) {
            return create_frames_of_region_ret_t {
                region: seL4_SlotRegion { start: 0, end: 0 },
                success: false,
            };
        }
        f += BIT!(PAGE_BITS);
    }
    unsafe {
        let slot_pos_after = ndks_boot.slot_pos_cur;
        return create_frames_of_region_ret_t {
            region: seL4_SlotRegion {
                start: slot_pos_before,
                end: slot_pos_after,
            },
            success: true,
        };
    }
}

pub fn create_ipcbuf_frame_cap(root_cnode_cap: &cap_t, pd_cap: &cap_t, vptr: usize) -> cap_t {
    unsafe {
        clearMemory(rootserver.ipc_buf as *mut u8, PAGE_BITS);
        let cap = rust_create_mapped_it_frame_cap(
            pd_cap,
            rootserver.ipc_buf,
            vptr,
            IT_ASID,
            false,
            false,
        );
        let ptr = cap_get_capPtr(root_cnode_cap) as *mut cte_t;
        write_slot(ptr.add(seL4_CapInitThreadIPCBuffer), cap.clone());
        return cap;
    }
}

pub fn rust_create_it_asid_pool(root_cnode_cap: &cap_t) -> cap_t {
    let ap_cap = unsafe { cap_asid_pool_cap_new(IT_ASID >> asidLowBits, rootserver.asid_pool) };
    let ptr = cap_get_capPtr(&root_cnode_cap) as *mut cte_t;
    unsafe {
        write_slot(ptr.add(seL4_CapInitThreadASIDPool), ap_cap.clone());
        write_slot(ptr.add(seL4_CapASIDControl), cap_asid_control_cap_new());
    }
    ap_cap
}

pub fn create_idle_thread() {
    unsafe {
        let pptr = ksIdleThreadTCB.as_ptr() as *mut usize;
        ksIdleThread = pptr.add(TCB_OFFSET) as *mut tcb_t;
        configureIdleThread(ksIdleThread as *const tcb_t);
    }
}

pub fn create_initial_thread(
    root_cnode_cap: &cap_t,
    it_pd_cap: &cap_t,
    ui_v_entry: usize,
    bi_frame_vptr: usize,
    ipcbuf_vptr: usize,
    ipcbuf_cap: cap_t,
) -> *mut tcb_t {
    let tcb = unsafe { (rootserver.tcb + TCB_OFFSET) as *mut tcb_t };
    unsafe {
        (*tcb).tcbTimeSlice = CONFIG_TIME_SLICE;

        (*tcb).tcbArch = Arch_initContext((*tcb).tcbArch);

        let ptr = cap_get_capPtr(root_cnode_cap) as *mut cte_t;
        let dc_ret = deriveCap(ptr.add(seL4_CapInitThreadIPCBuffer), &ipcbuf_cap.clone());
        if dc_ret.status != exception_t::EXCEPTION_NONE {
            println!("Failed to derive copy of IPC Buffer\n");
            return 0 as *mut tcb_t;
        }
        cteInsert(
            &root_cnode_cap.clone(),
            ptr.add(seL4_CapInitThreadCNode),
            getCSpace(rootserver.tcb, tcbCTable),
        );
        cteInsert(
            &it_pd_cap.clone(),
            ptr.add(seL4_CapInitThreadVspace),
            getCSpace(rootserver.tcb, tcbVTable),
        );
        cteInsert(
            &dc_ret.cap.clone(),
            ptr.add(seL4_CapInitThreadIPCBuffer),
            getCSpace(rootserver.tcb, tcbBuffer),
        );
        (*tcb).tcbIPCBuffer = ipcbuf_vptr;

        setRegister(tcb, capRegister, bi_frame_vptr);
        setNextPC(tcb, ui_v_entry);

        (*tcb).tcbMCP = seL4_MaxPrio;
        (*tcb).tcbPriority = seL4_MaxPrio;
        setThreadState(tcb, ThreadStateRunning);
        setupReplyMaster(tcb);
        ksCurDomain = ksDomSchedule[ksDomScheduleIdx].domain;
        ksDomainTime = ksDomSchedule[ksDomScheduleIdx].length;

        let cap = cap_thread_cap_new(tcb as usize);
        write_slot(ptr.add(seL4_CapInitThreadTCB), cap);
        forget(*tcb);
        tcb
    }
}

pub fn init_core_state(scheduler_action: *mut tcb_t) {
    unsafe {
        if scheduler_action as usize != 0 && scheduler_action as usize != 1 {
            tcbDebugAppend(scheduler_action);
        }
        tcbDebugAppend(ksIdleThread);
        ksSchedulerAction = scheduler_action as *mut tcb_t;
        ksCurThread = ksIdleThread;
    }
}

pub fn pptr_in_kernel_window(pptr: usize) -> bool {
    pptr >= PPTR_BASE && pptr < PPTR_TOP
}

pub fn provide_untyped_cap(
    root_cnode_cap: &cap_t,
    device_memory: bool,
    pptr: usize,
    size_bits: usize,
    first_untyped_slot: seL4_SlotPos,
) -> bool {
    if size_bits > seL4_MaxUntypedBits || size_bits < seL4_MinUntypedBits {
        println!("Kernel init: Invalid untyped size {}", size_bits);
        return false;
    }

    if !IS_ALIGNED!(pptr, size_bits) {
        println!(
            "Kernel init: Unaligned untyped pptr {} (alignment {})",
            pptr, size_bits
        );
        return false;
    }

    if !device_memory && !pptr_in_kernel_window(pptr) {
        println!(
            "Kernel init: Non-device untyped pptr {} outside kernel window",
            pptr
        );
        return false;
    }

    if !device_memory && !pptr_in_kernel_window(pptr + MASK!(size_bits)) {
        println!(
            "Kernel init: End of non-device untyped at {} outside kernel window (size {})",
            pptr, size_bits
        );
        return false;
    }
    let ret: bool;
    unsafe {
        let i = ndks_boot.slot_pos_cur - first_untyped_slot;
        if i < CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS {
            (*ndks_boot.bi_frame).untypedList[i] = seL4_UntypedDesc {
                paddr: pptr_to_paddr(pptr),
                sizeBits: size_bits as u8,
                isDevice: device_memory as u8,
                padding: [0; 6],
            };
            let ut_cap = cap_untyped_cap_new(
                MAX_FREE_INDEX(size_bits),
                device_memory as usize,
                size_bits,
                pptr,
            );
            ret = provide_cap(root_cnode_cap, ut_cap.clone());
        } else {
            println!("Kernel init: Too many untyped regions for boot info");
            ret = true
        }
    }
    ret
}

pub fn create_untypeds_for_region(
    root_cnode_cap: &cap_t,
    device_memory: bool,
    mut reg: region_t,
    first_untyped_slot: seL4_SlotPos,
) -> bool {
    // println!("{:#x} {:#x}", reg.start, reg.end);
    while !is_reg_empty(&reg) {
        let mut size_bits = seL4_WordBits - 1 - (reg.end - reg.start).leading_zeros() as usize;
        if size_bits > seL4_MaxUntypedBits {
            size_bits = seL4_MaxUntypedBits;
        }
        if reg.start != 0 {
            let align_bits = reg.start.trailing_zeros() as usize;
            if size_bits > align_bits {
                size_bits = align_bits;
            }
        }
        if size_bits >= seL4_MinUntypedBits {
            if !provide_untyped_cap(
                root_cnode_cap,
                device_memory,
                reg.start,
                size_bits,
                first_untyped_slot,
            ) {
                return false;
            }
        }
        reg.start += BIT!(size_bits);
        // println!("start :{:#x} end:{:#x}",reg.start ,reg.end);
    }
    return true;
}

pub fn create_untypeds(root_cnode_cap: &cap_t, boot_mem_reuse_reg: region_t) -> bool {
    unsafe {
        let first_untyped_slot = ndks_boot.slot_pos_cur;
        let mut start = 0;
        for i in 0..ndks_boot.resv_count {
            let reg = paddr_to_pptr_reg(&p_region_t {
                start: start,
                end: ndks_boot.reserved[i].start,
            });
            if !create_untypeds_for_region(root_cnode_cap, true, reg.clone(), first_untyped_slot) {
                println!(
                    "ERROR: creation of untypeds for device region {} at
                       [{}..{}] failed\n",
                    i, reg.start, reg.end
                );
                return false;
            }
            start = ndks_boot.reserved[i].end;
        }

        if start < CONFIG_PADDR_USER_DEVICE_TOP {
            let reg = paddr_to_pptr_reg(&p_region_t {
                start: start,
                end: CONFIG_PADDR_USER_DEVICE_TOP,
            });
            if !create_untypeds_for_region(root_cnode_cap, true, reg.clone(), first_untyped_slot) {
                println!(
                    "ERROR: creation of untypeds for top device region 
                       [{}..{}] failed\n",
                    reg.start, reg.end
                );
                return false;
            }
        }
        if !create_untypeds_for_region(
            root_cnode_cap,
            false,
            boot_mem_reuse_reg,
            first_untyped_slot,
        ) {
            println!(
                "ERROR: creation of untypeds for recycled boot memory
                   [{}..{}] failed\n",
                boot_mem_reuse_reg.start, boot_mem_reuse_reg.end
            );
            return false;
        }

        for i in 0..ndks_boot.freemem.len() {
            let reg = ndks_boot.freemem[i];
            ndks_boot.freemem[i] = region_t { start: 0, end: 0 };
            if !create_untypeds_for_region(root_cnode_cap, false, reg, first_untyped_slot) {
                println!(
                    "ERROR: creation of untypeds for free memory region :{} at
                [{}..{}] failed\n",
                    i, reg.start, reg.end
                );
            }
        }
        (*ndks_boot.bi_frame).untyped = seL4_SlotRegion {
            start: first_untyped_slot,
            end: ndks_boot.slot_pos_cur,
        };
        true
    }
}

pub fn bi_finalise() {
    unsafe {
        (*ndks_boot.bi_frame).empty = seL4_SlotRegion {
            start: ndks_boot.slot_pos_cur,
            end: BIT!(CONFIG_ROOT_CNODE_SIZE_BITS),
        };
    }
}

#[no_mangle]
pub extern "C" fn rust_try_init_kernel(
    ui_p_reg_start: usize,
    ui_p_reg_end: usize,
    pv_offset: isize,
    v_entry: usize,
    dtb_phys_addr: usize,
    dtb_size: usize,
) -> bool {
    extern "C" {
        fn ki_boot_end();
    }
    let boot_mem_reuse_p_reg = p_region_t {
        start: kpptr_to_paddr(KERNEL_ELF_BASE),
        end: kpptr_to_paddr(ki_boot_end as usize),
    };
    let boot_mem_reuse_reg = paddr_to_pptr_reg(&boot_mem_reuse_p_reg);
    let ui_reg = paddr_to_pptr_reg(&p_region_t {
        start: ui_p_reg_start,
        end: ui_p_reg_end,
    });

    let ui_p_reg = p_region_t {
        start: ui_p_reg_start,
        end: ui_p_reg_end,
    };
    let mut extra_bi_size = 0;
    let mut extra_bi_offset = 0;
    let ui_v_reg = v_region_t {
        start: (ui_p_reg_start as isize - pv_offset) as usize,
        end: (ui_p_reg_end as isize - pv_offset) as usize,
    };
    let ipcbuf_vptr = ui_v_reg.end;
    let bi_frame_vptr = ipcbuf_vptr + BIT!(PAGE_BITS);
    let extra_bi_frame_vptr = bi_frame_vptr + BIT!(BI_FRAME_SIZE_BITS);
    rust_map_kernel_window();
    init_cpu();
    // println!("Bootstrapping kernel\n");

    unsafe {
        init_plat();
    }

    let mut dtb_p_reg = p_region_t { start: 0, end: 0 };
    if dtb_size > 0 {
        let dtb_phys_end = dtb_phys_addr + dtb_size;
        if dtb_phys_end < dtb_phys_addr {
            println!(
                "ERROR: DTB location at {}
             len {} invalid",
                dtb_phys_addr, dtb_size
            );
            return false;
        }
        if dtb_phys_end >= PADDR_TOP {
            println!(
                "ERROR: DTB at [{}..{}] exceeds PADDR_TOP ({})\n",
                dtb_phys_addr, dtb_phys_end, PADDR_TOP
            );
            return false;
        }

        extra_bi_size += core::mem::size_of::<seL4_BootInfoHeader>() + dtb_size;
        dtb_p_reg = p_region_t {
            start: dtb_phys_addr,
            end: dtb_phys_end,
        };
    }
    let extra_bi_size_bits = calculate_extra_bi_size_bits(extra_bi_size);

    let it_v_reg = v_region_t {
        start: ui_v_reg.start,
        end: extra_bi_frame_vptr + BIT!(extra_bi_size_bits),
    };

    if it_v_reg.end >= USER_TOP {
        println!(
            "ERROR: userland image virt [{}..{}]
        exceeds USER_TOP ({})\n",
            it_v_reg.start, it_v_reg.end, USER_TOP
        );
        return false;
    }
    if !rust_arch_init_freemem(
        ui_reg.clone(),
        dtb_p_reg.clone(),
        it_v_reg.clone(),
        extra_bi_size_bits,
    ) {
        println!("ERROR: free memory management initialization failed\n");
        return false;
    }
    let root_cnode_cap = create_root_cnode();
    if cap_get_capType(&root_cnode_cap) == cap_null_cap {
        println!("ERROR: root c-node creation failed\n");
        return false;
    }
    create_domain_cap(&root_cnode_cap);
    init_irqs(&root_cnode_cap);
    rust_populate_bi_frame(0, CONFIG_MAX_NUM_NODES, ipcbuf_vptr, extra_bi_size);
    let mut header: seL4_BootInfoHeader = seL4_BootInfoHeader { id: 0, len: 0 };
    if dtb_size > 0 {
        header.id = SEL4_BOOTINFO_HEADER_FDT;
        header.len = size_of::<seL4_BootInfoHeader>() + dtb_size;
        unsafe {
            *((rootserver.extra_bi + extra_bi_offset) as *mut seL4_BootInfoHeader) = header.clone();
        }
        extra_bi_offset += size_of::<seL4_BootInfoHeader>();
        let src = unsafe {
            core::slice::from_raw_parts(paddr_to_pptr(dtb_phys_addr) as *const u8, dtb_size)
        };
        unsafe {
            let dst = core::slice::from_raw_parts_mut(
                (rootserver.extra_bi + extra_bi_offset) as *mut u8,
                dtb_size,
            );
            dst.copy_from_slice(src);
        }
    }
    if extra_bi_size > extra_bi_offset {
        header.id = SEL4_BOOTINFO_HEADER_PADDING;
        header.len = extra_bi_size - extra_bi_offset;
        unsafe {
            *((rootserver.extra_bi + extra_bi_offset) as *mut seL4_BootInfoHeader) = header.clone();
        }
    }
    let it_pd_cap = rust_create_it_address_space(&root_cnode_cap, it_v_reg);
    if cap_get_capType(&it_pd_cap) == cap_null_cap {
        println!("ERROR: address space creation for initial thread failed");
        return false;
    }
    create_bi_frame_cap(&root_cnode_cap, &it_pd_cap, bi_frame_vptr);
    if extra_bi_size > 0 {
        let extra_bi_region = unsafe {
            region_t {
                start: rootserver.extra_bi,
                end: rootserver.extra_bi + extra_bi_size,
            }
        };
        let extra_bi_ret = rust_create_frames_of_region(
            &root_cnode_cap,
            &it_pd_cap,
            extra_bi_region,
            true,
            pptr_to_paddr(extra_bi_region.start) as isize - extra_bi_frame_vptr as isize,
        );

        if !extra_bi_ret.success {
            println!("ERROR: mapping extra boot info to initial thread failed");
            return false;
        }
        unsafe {
            (*ndks_boot.bi_frame).extraBIPages = extra_bi_ret.region;
        }
    }
    let ipcbuf_cap = create_ipcbuf_frame_cap(&root_cnode_cap, &it_pd_cap, ipcbuf_vptr);
    if cap_get_capType(&ipcbuf_cap) == cap_null_cap {
        println!("ERROR: could not create IPC buffer for initial thread");
        return false;
    }
    let create_frames_ret = rust_create_frames_of_region(
        &root_cnode_cap,
        &it_pd_cap,
        ui_reg,
        true,
        pv_offset as isize,
    );
    if !create_frames_ret.success {
        println!("ERROR: could not create all userland image frames");
        return false;
    }
    unsafe {
        (*ndks_boot.bi_frame).userImageFrames = create_frames_ret.region;
    }
    let it_ap_cap = rust_create_it_asid_pool(&root_cnode_cap);
    if cap_get_capType(&it_ap_cap) == cap_null_cap {
        println!("ERROR: could not create ASID pool for initial thread");
        return false;
    }
    write_it_asid_pool(&it_ap_cap, &it_pd_cap);
    create_idle_thread();

    let initial = create_initial_thread(
        &root_cnode_cap,
        &it_pd_cap,
        v_entry,
        bi_frame_vptr,
        ipcbuf_vptr,
        ipcbuf_cap,
    );
    forget(it_pd_cap);
    if initial as usize == 0 {
        println!("ERROR: could not create initial thread");
        return false;
    }
    init_core_state(initial);
    if !create_untypeds(&root_cnode_cap, boot_mem_reuse_reg) {
        println!("ERROR: could not create untypteds for kernel image boot memory");
    }

    unsafe {
        (*ndks_boot.bi_frame).sharedFrames = seL4_SlotRegion { start: 0, end: 0 };

        bi_finalise();

        forget(*initial);
        forget(*ksSchedulerAction);
        let arr = core::slice::from_raw_parts_mut(
            rootserver_mem.start as *mut u8,
            rootserver_mem.end - rootserver_mem.start,
        );
        forget(arr);
        for i in rootserver_mem.start..rootserver_mem.end {
            let ptr = *(i as *mut u8);
            forget(ptr);
        }
        let ptr = *getCSpace(rootserver.tcb, tcbVTable);
        forget(ptr);

        let cptr = *getCSpace(rootserver.tcb, tcbCTable);
        forget(cptr);
        let bptr = *getCSpace(rootserver.tcb, tcbBuffer);
        forget(bptr);
        forget(ksIdleThreadTCB);

        println!("idle thread:{:#x}", ksIdleThreadTCB.as_ptr() as usize);

        println!("initial thread :{:#x}", initial as usize);
    }

    println!("Booting all finished, dropped to user space");
    println!("\n");
    true
}

// pub extern "C" fn init_kernel(
//     ui_p_reg_start: usize,
//     ui_p_reg_end: usize,
//     pv_offset: usize,
//     v_entry: usize,
//     dtb_addr_p: usize,
//     dtb_size: usize,
// ) {
// }
