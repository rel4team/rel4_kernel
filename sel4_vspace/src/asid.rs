#[cfg(target_arch = "riscv64")]
use core::arch::asm;
use core::intrinsics::unlikely;

use super::interface::set_vm_root;
use crate::arch::pte_t;
use crate::structures::pptr_t;
use sel4_common::{
    fault::*, sel4_config::*, structures::exception_t, utils::convert_to_option_mut_type_ref, BIT,
    MASK,
};
use sel4_cspace::interface::cap_t;

#[no_mangle]
pub static mut riscvKSASIDTable: [*mut asid_pool_t; BIT!(asidHighBits)] =
    [0 as *mut asid_pool_t; BIT!(asidHighBits)];

#[derive(Copy, Clone)]
pub struct asid_pool_t {
    pub array: [*mut pte_t; BIT!(asidLowBits)],
}

impl asid_pool_t {
    #[inline]
    pub fn get_ptr(&self) -> pptr_t {
        self as *const Self as pptr_t
    }

    #[inline]
    pub fn get_vspace_by_index(&mut self, index: usize) -> Option<&'static mut pte_t> {
        convert_to_option_mut_type_ref::<pte_t>(self.array[index] as usize)
    }

    #[inline]
    pub fn set_vspace_by_index(&mut self, index: usize, vspace_ptr: pptr_t) {
        // assert!(index < BIT!(asidLowBits));
        self.array[index] = vspace_ptr as *mut pte_t;
    }
}

#[allow(non_camel_case_types)]
pub type asid_t = usize;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct findVSpaceForASID_ret {
    pub status: exception_t,
    pub vspace_root: Option<*mut pte_t>,
    pub lookup_fault: Option<lookup_fault_t>,
}

#[inline]
pub fn get_asid_pool_by_index(index: usize) -> Option<&'static mut asid_pool_t> {
    unsafe {
        if unlikely(index >= BIT!(asidHighBits)) {
            return None;
        }
        return convert_to_option_mut_type_ref::<asid_pool_t>(riscvKSASIDTable[index] as usize);
    }
}

pub fn set_asid_pool_by_index(index: usize, pool_ptr: pptr_t) {
    // assert!(index < BIT!(asidHighBits));
    unsafe {
        riscvKSASIDTable[index] = pool_ptr as *mut asid_pool_t;
    }
}

#[no_mangle]
pub fn find_vspace_for_asid(asid: asid_t) -> findVSpaceForASID_ret {
    let mut ret: findVSpaceForASID_ret = findVSpaceForASID_ret {
        status: exception_t::EXCEPTION_FAULT,
        vspace_root: None,
        lookup_fault: None,
    };

    let poolPtr = unsafe { riscvKSASIDTable[asid >> asidLowBits] };
    if poolPtr as usize == 0 {
        ret.lookup_fault = Some(lookup_fault_t::new_root_invalid());
        ret.vspace_root = None;
        ret.status = exception_t::EXCEPTION_LOOKUP_FAULT;
        return ret;
    }
    let vspace_root = unsafe { (*poolPtr).array[asid & MASK!(asidLowBits)] };
    if vspace_root as usize == 0 {
        ret.lookup_fault = Some(lookup_fault_t::new_root_invalid());
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
pub fn findVSpaceForASID(_asid: asid_t) -> findVSpaceForASID_ret {
    panic!("should not be invoked!")
}

#[inline]
fn hwASIDFlush(_asid: asid_t) {
    #[cfg(target_arch = "aarch64")]
    todo!("hwASIDFlush");
    #[cfg(target_arch = "riscv64")]
    unsafe {
        asm!("sfence.vma x0, {0}",in(reg) _asid);
    }
}

pub fn delete_asid_pool(
    asid_base: asid_t,
    pool: *mut asid_pool_t,
    default_vspace_cap: &cap_t,
) -> Result<(), lookup_fault_t> {
    unsafe {
        if riscvKSASIDTable[asid_base >> asidLowBits] == pool {
            riscvKSASIDTable[asid_base >> asidLowBits] = 0 as *mut asid_pool_t;
            set_vm_root(default_vspace_cap)
        } else {
            Ok(())
        }
    }
}

pub fn delete_asid(
    asid: asid_t,
    vspace: *mut pte_t,
    default_vspace_cap: &cap_t,
) -> Result<(), lookup_fault_t> {
    unsafe {
        let poolPtr = riscvKSASIDTable[asid >> asidLowBits];
        if poolPtr as usize != 0 && (*poolPtr).array[asid & MASK!(asidLowBits)] == vspace {
            hwASIDFlush(asid);
            (*poolPtr).array[asid & MASK!(asidLowBits)] = 0 as *mut pte_t;
            set_vm_root(&default_vspace_cap)
        } else {
            Ok(())
        }
    }
}
