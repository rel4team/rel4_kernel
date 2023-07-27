use core::arch::asm;

use super::{pte::pte_t, riscvKSASIDTable};
use common::{BIT, structures::exception_t, MASK};
use crate::{config::asidLowBits, structures::lookup_fault_t, object::structure_gen::lookup_fault_invalid_root_new};

#[derive(Copy, Clone)]
pub struct asid_pool_t {
    pub array: [*mut pte_t; BIT!(asidLowBits)],
}

pub type asid_t = usize;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct findVSpaceForASID_ret {
    pub status: exception_t,
    pub vspace_root: Option<*mut pte_t>,
    pub lookup_fault: Option<lookup_fault_t>,
}

#[no_mangle]
pub fn find_vspace_for_asid(asid: asid_t) -> findVSpaceForASID_ret {
    let mut ret: findVSpaceForASID_ret = findVSpaceForASID_ret {
        status: exception_t::EXCEPTION_FAULT,
        vspace_root: None,
        lookup_fault: None,
    };

    let poolPtr =  unsafe {
        riscvKSASIDTable[asid >> asidLowBits]
    };
    if poolPtr as usize == 0 {
        ret.lookup_fault = Some(lookup_fault_invalid_root_new());
        ret.vspace_root = None;
        ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
        return ret;
    }
    let vspace_root = unsafe {
        (*poolPtr).array[asid & MASK!(asidLowBits)]
    };
    if vspace_root as usize == 0 {
        ret.lookup_fault = Some(lookup_fault_invalid_root_new());
        ret.vspace_root = None;
        ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
        return ret;
    }
    ret.vspace_root = Some(vspace_root);
    ret.status = exception_t::EXCEPTION_NONE;
    // vspace_root0xffffffc17fec1000
    return ret;
}

#[no_mangle]
pub fn findVSpaceForASID(asid: asid_t) -> findVSpaceForASID_ret {
    find_vspace_for_asid(asid)
}

pub fn hwASIDFlush(asid: asid_t) {
    unsafe {
        asm!("sfence.vma x0, {0}",in(reg) asid);
    }
}
