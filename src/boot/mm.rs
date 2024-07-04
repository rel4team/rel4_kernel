use log::debug;

use super::ndks_boot;
use crate::boot::utils::ceiling_kernel_window;
use crate::boot::utils::is_reg_empty;
use crate::boot::utils::paddr_to_pptr_reg;
use crate::boot::utils::pptr_to_paddr_reg;
use crate::config::*;
use crate::structures::*;

#[link_section = ".boot.bss"]
static mut avail_reg: [region_t; MAX_NUM_FREEMEM_REG] =
    [region_t { start: 0, end: 0 }; MAX_NUM_FREEMEM_REG];

#[link_section = ".boot.bss"]
pub static mut res_reg: [region_t; NUM_RESERVED_REGIONS] =
    [region_t { start: 0, end: 0 }; NUM_RESERVED_REGIONS];

#[link_section = ".boot.bss"]
pub static mut avail_p_regs_size: usize = 0;

#[link_section = ".boot.bss"]
pub static mut avail_p_regs_addr: usize = 0;

pub fn rust_init_freemem(
    n_available: usize,
    available: usize,
    n_reserved: usize,
    reserved: [region_t; NUM_RESERVED_REGIONS],
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
        if !is_reg_empty(&ndks_boot.freemem[ndks_boot.freemem.len() - 1]) {
            debug!(
                "ERROR: insufficient MAX_NUM_FREEMEM_REG {}\n",
                MAX_NUM_FREEMEM_REG
            );
            return false;
        }
    }
    true
}

fn check_available_memory(n_available: usize, available: usize) -> bool {
    if n_available == 0 {
        debug!("ERROR: no memory regions available");
        return false;
    }
    debug!("available phys memory regions: {:#x}", n_available);
    let mut last: p_region_t = unsafe { (*(available as *const p_region_t).add(0)).clone() };
    for i in 0..n_available {
        let r: p_region_t;
        unsafe {
            r = (*(available as *const p_region_t).add(i)).clone();
        }
        debug!(" [{:#x}..{:#x}]", r.start, r.end);

        if r.start > r.end {
            debug!("ERROR: memory region {} has start > end", i);
            return false;
        }

        if r.start == r.end {
            debug!("ERROR: memory region {} empty", i);
            return false;
        }
        if i > 0 && r.start < last.end {
            debug!("ERROR: memory region {} in wrong order", i);
        }
        last = r.clone();
    }
    return true;
}

fn check_reserved_memory(n_reserved: usize, reserved: [region_t; NUM_RESERVED_REGIONS]) -> bool {
    debug!("reserved virt address space regions: {}", n_reserved);
    let mut last: region_t = reserved[0].clone();
    for i in 0..n_reserved {
        let r: region_t;
        r = reserved[i].clone();
        debug!("  [{:#x}..{:#x}]", r.start, r.end);
        if r.start > r.end {
            debug!("ERROR: reserved region {} has start > end\n", i);
            return false;
        }

        if i > 0 && r.start < last.end {
            debug!("ERROR: reserved region {} in wrong order", i);
            return false;
        }
        last = r.clone();
    }
    true
}

fn insert_region(reg: region_t) -> bool {
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
    debug!(
        "no free memory slot left for [{}..{}],
     consider increasing MAX_NUM_FREEMEM_REG (%{})\n",
        reg.start, reg.end, MAX_NUM_FREEMEM_REG
    );
    assert!(false);
    return false;
}

pub unsafe fn reserve_region(reg: p_region_t) -> bool {
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
                debug!("Can't mark region {:#x}-{:#x} as reserved, try increasing MAX_NUM_RESV_REG (currently {})\n",reg.start,reg.end,MAX_NUM_RESV_REG);
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
        debug!("Can't mark region 0x{}-0x{} as reserved, try increasing MAX_NUM_RESV_REG (currently {})\n",reg.start,reg.end,MAX_NUM_RESV_REG);
        return false;
    }
    ndks_boot.reserved[i] = reg;
    ndks_boot.resv_count += 1;
    return true;
}

unsafe fn merge_regions() {
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
