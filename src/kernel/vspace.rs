use core::intrinsics::unlikely;
use common::message_info::*;
use common::structures::{lookup_fault_invalid_root_new, seL4_Fault_VMFault_new, seL4_IPCBuffer};
use common::utils::{pageBitsForSize, convert_to_option_type_ref};
use common::{BIT, MASK};
use common::{structures::exception_t, sel4_config::*};
use log::debug;
use vspace::*;
use crate::syscall::ensureEmptySlot;
use crate::syscall::invocation::decode::decode_mmu_invocation::{decode_page_table_invocation, decodeRISCVFrameInvocation};
use crate::utils::clear_memory;
use crate::{
    config::{
        seL4_ASIDPoolBits, RISCVInstructionAccessFault,
        RISCVInstructionPageFault, RISCVLoadAccessFault, RISCVLoadPageFault,
        RISCVStoreAccessFault, RISCVStorePageFault
    },
    kernel::boot::current_syscall_error,
    riscv::read_stval,
    syscall::getSyscallArg,
    utils::MAX_FREE_INDEX,

};
use cspace::compatibility::*;
use task_manager::*;

use super::{
    boot::{
        current_extra_caps, current_fault, current_lookup_fault,
    },
    cspace::rust_lookupTargetSlot,
};

use cspace::interface::*;

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
        if let Err(lookup_fault) = delete_asid_pool(asid_base, pool, &(*getCSpace(ksCurThread as usize, tcbVTable)).cap) {
            current_lookup_fault = lookup_fault;
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
    clear_memory(frame as *mut u8, pageBitsForSize(RISCV_4K_Page));
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
        if let Err(lookup_fault) = delete_asid(asid, vspace, &(*getCSpace(ksCurThread as usize, tcbVTable)).cap) {
            current_lookup_fault = lookup_fault;
        }
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
pub fn decodeRISCVMMUInvocation(
    label: MessageLabel,
    length: usize,
    _cptr: usize,
    cte: *mut cte_t,
    cap: &mut cap_t,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    match cap_get_capType(cap) {
        cap_page_table_cap => decode_page_table_invocation(label, length, unsafe { &mut *cte }, convert_to_option_type_ref::<seL4_IPCBuffer>(buffer as usize)),
        cap_frame_cap => decodeRISCVFrameInvocation(label, length, cte, cap, call, buffer),
        cap_asid_control_cap => {
            // debug!("in cap_asid_control_cap");
            if label != MessageLabel::RISCVASIDControlMakePool {
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
                unsafe {
                    current_syscall_error._type = seL4_RevokeFirst;
                }
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
            // debug!("in cap_asid_pool_cap");
            if label != MessageLabel::RISCVASIDPoolAssign {
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
                    debug!("RISCVASIDPool: Invalid vspace root.");
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
