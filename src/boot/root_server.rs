use super::calculate_extra_bi_size_bits;
use super::utils::{arch_get_n_paging, write_slot, provide_cap, create_it_pt_cap, map_it_frame_cap};
use super::{ndks_boot, utils::is_reg_empty};
use common::{BIT, ROUND_DOWN};
use common::sel4_config::{wordBits, seL4_SlotBits, IT_ASID, asidLowBits, seL4_PageBits, seL4_PageTableBits, CONFIG_PT_LEVELS,
    PAGE_BITS, CONFIG_MAX_NUM_NODES, TCB_OFFSET, CONFIG_TIME_SLICE, tcbCTable, tcbVTable, tcbBuffer, CONFIG_NUM_DOMAINS, seL4_TCBBits};
use common::structures::{exception_t, seL4_IPCBuffer};
use cspace::compatibility::*;
use cspace::interface::*;
use log::debug;
use crate::interrupt::{setIRQState, IRQInactive, IRQTimer};
use crate::kernel::thread::Arch_initContext;
use crate::structures::{region_t, rootserver_mem_t, v_region_t, seL4_SlotRegion, create_frames_of_region_ret_t,
    seL4_BootInfo};

use crate::config::*;
use crate::utils::clear_memory;

use task_manager::*;
use vspace::*;
#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut rootserver_mem: region_t = region_t { start: 0, end: 0 };

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

pub fn root_server_init(it_v_reg: v_region_t, extra_bi_size_bits: usize, ipcbuf_vptr: usize, bi_frame_vptr: usize,
    extra_bi_size: usize, extra_bi_frame_vptr: usize, ui_reg: region_t, pv_offset: isize, v_entry: usize) -> Option<(*mut tcb_t, cap_t)> {

    unsafe {
        root_server_mem_init(it_v_reg, extra_bi_size_bits);
    }
    
    let root_cnode_cap = unsafe {
        create_root_cnode()
    };
    if root_cnode_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("ERROR: root c-node creation failed\n");
        return None;
    }

    create_domain_cap(&root_cnode_cap);
    init_irqs(&root_cnode_cap);
    unsafe {
        rust_populate_bi_frame(0, CONFIG_MAX_NUM_NODES, ipcbuf_vptr, extra_bi_size);
    }
    let it_pd_cap = unsafe {
        rust_create_it_address_space(&root_cnode_cap, it_v_reg)
    };
    if it_pd_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("ERROR: address space creation for initial thread failed");
        return None;
    }

    if !init_bi_frame_cap(root_cnode_cap, it_pd_cap, bi_frame_vptr, extra_bi_size, extra_bi_frame_vptr) {
        return None;
    }
    let ipcbuf_cap = unsafe {
        create_ipcbuf_frame_cap(&root_cnode_cap, &it_pd_cap, ipcbuf_vptr)
    };
    if ipcbuf_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("ERROR: could not create IPC buffer for initial thread");
        return None;
    }

    if ipcbuf_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("ERROR: could not create IPC buffer for initial thread");
        return None;
    }
    if !create_frame_ui_frames(root_cnode_cap, it_pd_cap, ui_reg, pv_offset) {
        return None;
    }

    if !asid_init(root_cnode_cap, it_pd_cap) {
        return None;
    }
    
    let initial = unsafe {
        create_initial_thread(
            &root_cnode_cap,
            &it_pd_cap,
            v_entry,
            bi_frame_vptr,
            ipcbuf_vptr,
            ipcbuf_cap,
        )
    };

    if initial as usize == 0 {
        debug!("ERROR: could not create initial thread");
        return None;
    }
    Some((initial, root_cnode_cap))
    
}



unsafe fn create_initial_thread(
    root_cnode_cap: &cap_t,
    it_pd_cap: &cap_t,
    ui_v_entry: usize,
    bi_frame_vptr: usize,
    ipcbuf_vptr: usize,
    ipcbuf_cap: cap_t,
) -> *mut tcb_t {
    let tcb = unsafe { (rootserver.tcb + TCB_OFFSET) as *mut tcb_t };
    (*tcb).tcbTimeSlice = CONFIG_TIME_SLICE;

    (*tcb).tcbArch = Arch_initContext();

    let ptr = root_cnode_cap.get_cap_ptr() as *mut cte_t;
    let cte = unsafe {
        &mut *(ptr.add(seL4_CapInitThreadIPCBuffer))
    };
    let dc_ret = cte.derive_cap(&ipcbuf_cap.clone());
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        debug!("Failed to derive copy of IPC Buffer\n");
        return 0 as *mut tcb_t;
    }
    cteInsert(
        &root_cnode_cap.clone(),
        unsafe { &mut *(ptr.add(seL4_CapInitThreadCNode)) },
        getCSpaceMutRef(rootserver.tcb, tcbCTable),
    );
    cteInsert(
        &it_pd_cap.clone(),
        unsafe { &mut *(ptr.add(seL4_CapInitThreadVspace)) },
        getCSpaceMutRef(rootserver.tcb, tcbVTable),
    );
    cteInsert(
        &dc_ret.cap.clone(),
        unsafe { &mut *(ptr.add(seL4_CapInitThreadIPCBuffer)) },
        getCSpaceMutRef(rootserver.tcb, tcbBuffer),
    );
    (*tcb).tcbIPCBuffer = ipcbuf_vptr;

    setRegister(tcb, capRegister, bi_frame_vptr);
    setNextPC(tcb, ui_v_entry);
    

    (*tcb).tcbMCP = seL4_MaxPrio;
    (*tcb).tcbPriority = seL4_MaxPrio;
    setThreadState(tcb, ThreadStateRunning);
    (*tcb).setup_reply_master();
    ksCurDomain = ksDomSchedule[ksDomScheduleIdx].domain;
    ksDomainTime = ksDomSchedule[ksDomScheduleIdx].length;

    let cap = cap_t::new_thread_cap(tcb as usize);
    let tmp = unsafe {
        &*(&cap as *const cap_t as usize as *const [usize; 2])
    };
    debug!("root server tcb cap: {:#x}, {:#x}, {:?}", tmp[0], tmp[1], cap);
    write_slot(ptr.add(seL4_CapInitThreadTCB), cap);
    // forget(*tcb);
    tcb
}

fn asid_init(root_cnode_cap: cap_t, it_pd_cap: cap_t) -> bool {
    let it_ap_cap = create_it_asid_pool(&root_cnode_cap);
    if it_ap_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("ERROR: could not create ASID pool for initial thread");
        return false;
    }
    
    unsafe {
        let ap = it_ap_cap.get_cap_ptr();
        let ptr = (ap + 8 * IT_ASID) as *mut usize;
        *ptr = it_pd_cap.get_cap_ptr();
        riscvKSASIDTable[IT_ASID >> asidLowBits] = ap as *mut asid_pool_t;
    }
    true
}


fn create_it_asid_pool(root_cnode_cap: &cap_t) -> cap_t {
    let ap_cap = unsafe { cap_t::new_asid_pool_cap(IT_ASID >> asidLowBits, rootserver.asid_pool) };
    unsafe {
        let ptr = root_cnode_cap.get_cap_ptr() as *mut cte_t;
        write_slot(ptr.add(seL4_CapInitThreadASIDPool), ap_cap.clone());
        write_slot(ptr.add(seL4_CapASIDControl), cap_t::new_asid_control_cap());
    }
    ap_cap
}

fn create_frame_ui_frames(root_cnode_cap: cap_t, it_pd_cap: cap_t, ui_reg: region_t, pv_offset: isize) -> bool {
    let create_frames_ret = rust_create_frames_of_region(
        &root_cnode_cap,
        &it_pd_cap,
        ui_reg,
        true,
        pv_offset as isize,
    );
    if !create_frames_ret.success {
        debug!("ERROR: could not create all userland image frames");
        return false;
    }
    unsafe {
        (*ndks_boot.bi_frame).userImageFrames = create_frames_ret.region;
    }
    true
}

unsafe fn root_server_mem_init(it_v_reg: v_region_t, extra_bi_size_bits: usize) {
    let size = calculate_rootserver_size(it_v_reg, extra_bi_size_bits);
    let max = rootserver_max_size_bits(extra_bi_size_bits);
    let mut i = ndks_boot.freemem.len() - 1;
    /* skip any empty regions */
    while i != usize::MAX && is_reg_empty(&ndks_boot.freemem[i]) {
        i -= 1;
    }
    while i != usize::MAX && i < ndks_boot.freemem.len() {
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
            return;
        }
        /* Region i isn't big enough, so shuffle it up to slot (i + 1),
            * which we know is unused. */
        ndks_boot.freemem[empty_index] = ndks_boot.freemem[i];
        ndks_boot.freemem[i] = region_t { start: 0, end: 0 };
        i -= 1;
    }
}

unsafe fn create_root_cnode() -> cap_t {
    let cap = cap_t::new_cnode_cap(
        CONFIG_ROOT_CNODE_SIZE_BITS,
        wordBits - CONFIG_ROOT_CNODE_SIZE_BITS,
        0,
        rootserver.cnode,
    );
    let ptr = rootserver.cnode as *mut cte_t;
    write_slot(ptr.add(seL4_CapInitThreadCNode), cap.clone());
    cap
}

fn calculate_rootserver_size(it_v_reg: v_region_t, extra_bi_size_bits: usize) -> usize {
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

fn rootserver_max_size_bits(extra_bi_size_bits: usize) -> usize {
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

fn alloc_rootserver_obj(size_bits: usize, n: usize) -> usize {
    unsafe {
        let allocated = rootserver_mem.start;
        assert!(allocated % BIT!(size_bits) == 0);
        rootserver_mem.start += n * BIT!(size_bits);
        assert!(rootserver_mem.start <= rootserver_mem.end);
        allocated
    }
}

#[inline]
unsafe fn it_alloc_paging() -> usize {
    let allocated = rootserver.paging.start;
    rootserver.paging.start += BIT!(seL4_PageTableBits);
    assert!(rootserver.paging.start <= rootserver.paging.end);
    allocated
}

unsafe fn maybe_alloc_extra_bi(cmp_size_bits: usize, extra_bi_size_bits: usize) {
    if extra_bi_size_bits >= cmp_size_bits && rootserver.extra_bi == 0 {
        rootserver.extra_bi = alloc_rootserver_obj(extra_bi_size_bits, 1);
    }
}

unsafe fn create_rootserver_objects(start: usize, it_v_reg: v_region_t, extra_bi_size_bits: usize) {
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

    assert_eq!(rootserver_mem.start, rootserver_mem.end);
}

fn create_domain_cap(root_cnode_cap: &cap_t) {
    assert!(ksDomScheduleLength > 0);
    for i in 0..ksDomScheduleLength {
        unsafe {
            assert!(ksDomSchedule[i].domain < CONFIG_NUM_DOMAINS);
            assert!(ksDomSchedule[i].length > 0);
        }
    }
    let cap = cap_t::new_domain_cap();
    unsafe {
        let pos = root_cnode_cap.get_cap_ptr() as *mut cte_t;
        write_slot(pos.add(seL4_CapDomain), cap);
    }
}

fn init_irqs(root_cnode_cap: &cap_t) {
    for i in 0..maxIRQ + 1 {
        if i != irqInvalid {
            setIRQState(IRQInactive, i);
        }
    }
    setIRQState(IRQTimer, KERNEL_TIMER_IRQ);
    unsafe {
        let ptr = root_cnode_cap.get_cap_ptr() as *mut cte_t;
        write_slot(ptr.add(seL4_CapIRQControl), cap_t::new_irq_control_cap());
    }
}

unsafe fn rust_create_it_address_space(root_cnode_cap: &cap_t, it_v_reg: v_region_t) -> cap_t {
    copyGlobalMappings(rootserver.vspace);
    let lvl1pt_cap = cap_t::new_page_table_cap(IT_ASID, rootserver.vspace, 1, rootserver.vspace);
    let ptr = root_cnode_cap.get_cap_ptr() as *mut cte_t;
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
                return cap_t::new_null_cap();
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


fn init_bi_frame_cap(root_cnode_cap: cap_t, it_pd_cap: cap_t, bi_frame_vptr: usize, extra_bi_size: usize, extra_bi_frame_vptr: usize) -> bool {
    unsafe {
        create_bi_frame_cap(&root_cnode_cap, &it_pd_cap, bi_frame_vptr);
    }
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
            debug!("ERROR: mapping extra boot info to initial thread failed");
            return false;
        }
        unsafe {
            (*ndks_boot.bi_frame).extraBIPages = extra_bi_ret.region;
        }
    }
    true

}


fn rust_create_frames_of_region(
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

unsafe fn create_bi_frame_cap(root_cnode_cap: &cap_t, pd_cap: &cap_t, vptr: usize) {
    let cap = rust_create_mapped_it_frame_cap(
        pd_cap,
        rootserver.boot_info,
        vptr,
        IT_ASID,
        false,
        false,
    );
    let ptr = root_cnode_cap.get_cap_ptr() as *mut cte_t;
    write_slot(ptr.add(seL4_CapBootInfoFrame), cap);
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
    let cap = cap_t::new_frame_cap(asid, pptr, frame_size, VMReadWrite, 0, vptr);
    map_it_frame_cap(pd_cap, &cap);
    cap
}


fn rust_create_unmapped_it_frame_cap(pptr: pptr_t, _use_large: bool) -> cap_t {
    cap_t::new_frame_cap(0, pptr, 0, 0, 0, 0)
}


unsafe fn rust_populate_bi_frame(
    node_id: usize,
    num_nodes: usize,
    ipcbuf_vptr: usize,
    extra_bi_size: usize,
) {
    clear_memory(rootserver.boot_info as *mut u8, BI_FRAME_SIZE_BITS);
    if extra_bi_size != 0 {
        clear_memory(
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
}

unsafe fn create_ipcbuf_frame_cap(root_cnode_cap: &cap_t, pd_cap: &cap_t, vptr: usize) -> cap_t {
    clear_memory(rootserver.ipc_buf as *mut u8, PAGE_BITS);
    let cap = rust_create_mapped_it_frame_cap(
        pd_cap,
        rootserver.ipc_buf,
        vptr,
        IT_ASID,
        false,
        false,
    );
    let ptr = root_cnode_cap.get_cap_ptr() as *mut cte_t;
    write_slot(ptr.add(seL4_CapInitThreadIPCBuffer), cap.clone());
    return cap;
}