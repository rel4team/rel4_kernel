use crate::config::*;
use crate::{
    kernel::vspace::{paddr_to_pptr, pptr_to_paddr, RISCV_GET_LVL_PGSIZE_BITS},
    object::{
        objecttype::cap_get_capPtr,
        structure_gen::{mdb_node_set_mdbFirstBadged, mdb_node_set_mdbRevocable},
    },
    println,
    structures::{cap_t, cte_t, mdb_node_t, p_region_t, region_t, v_region_t},
    BIT, ROUND_DOWN, ROUND_UP,
};

use super::ndks_boot;

#[inline]
pub fn is_reg_empty(reg: &region_t) -> bool {
    reg.start == reg.end
}

#[inline]
pub fn paddr_to_pptr_reg(reg: &p_region_t) -> region_t {
    region_t {
        start: paddr_to_pptr(reg.start),
        end: paddr_to_pptr(reg.end),
    }
}

pub fn ceiling_kernel_window(mut p: usize) -> usize {
    if pptr_to_paddr(p) > PADDR_TOP {
        p = PPTR_TOP;
    }
    p
}

#[inline]
pub fn pptr_to_paddr_reg(reg: region_t) -> p_region_t {
    p_region_t {
        start: pptr_to_paddr(reg.start),
        end: pptr_to_paddr(reg.end),
    }
}

pub fn pptr_in_kernel_window(pptr: usize) -> bool {
    pptr >= PPTR_BASE && pptr < PPTR_TOP
}

#[inline]
pub fn get_n_paging(v_reg: v_region_t, bits: usize) -> usize {
    let start = ROUND_DOWN!(v_reg.start, bits);
    let end = ROUND_UP!(v_reg.end, bits);
    (end - start) / BIT!(bits)
}

pub fn arch_get_n_paging(it_v_reg: v_region_t) -> usize {
    let mut n: usize = 0;
    for i in 0..CONFIG_PT_LEVELS - 1 {
        n += get_n_paging(it_v_reg, RISCV_GET_LVL_PGSIZE_BITS(i));
    }
    return n;
}

pub fn write_slot(ptr: *mut cte_t, cap: cap_t) {
    unsafe {
        (*ptr).cap = cap;
        (*ptr).cteMDBNode = mdb_node_t::default();

        mdb_node_set_mdbRevocable(&mut (*ptr).cteMDBNode, 1);
        mdb_node_set_mdbFirstBadged(&mut (*ptr).cteMDBNode, 1);
        // forget(*ptr);
    }
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

#[inline]
pub fn clearMemory(ptr: *mut u8, bits: usize) {
    unsafe {
        core::slice::from_raw_parts_mut(ptr, BIT!(bits)).fill(0);
    }
}
