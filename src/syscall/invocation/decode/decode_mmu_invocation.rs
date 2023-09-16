use core::intrinsics::unlikely;

use common::{
    message_info::MessageLabel, structures::{exception_t, seL4_IPCBuffer}, 
    sel4_config::*, MASK, 
    utils::convert_to_mut_type_ref,
};
use cspace::interface::{cte_t, CapTag};
use log::debug;
use task_manager::{set_thread_state, get_currenct_thread, ThreadState};
use vspace::{find_vspace_for_asid, pte_t};

use crate::{
    kernel::boot::{current_syscall_error, current_lookup_fault, get_extra_cap_by_index},
    syscall::{invocation::invoke_mmu_op::{invoke_page_table_unmap, invoke_page_table_map}, get_syscall_arg},
    config::USER_TOP
};

pub fn decode_page_table_invocation(label: MessageLabel, length: usize, cte: &mut cte_t, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    match label {
        MessageLabel::RISCVPageTableUnmap => decode_page_table_unmap(cte),

        MessageLabel::RISCVPageTableMap => decode_page_table_map(length, cte, buffer),
        _ => {
            debug!("RISCVPageTable: Illegal Operation");
            unsafe { current_syscall_error._type = seL4_IllegalOperation; }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
}

fn decode_page_table_unmap(pt_cte: &mut cte_t) -> exception_t {
    if !pt_cte.is_final_cap() {
        debug!("RISCVPageTableUnmap: cannot unmap if more than once cap exists");
        unsafe { current_syscall_error._type = seL4_RevokeFirst; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let cap = &mut pt_cte.cap;
    if cap.get_pt_is_mapped() != 0 {
        let asid = cap.get_pt_mapped_asid();
        let find_ret = find_vspace_for_asid(asid);
        let pte_ptr = cap.get_pt_base_ptr() as *mut pte_t;
        if find_ret.status == exception_t::EXCEPTION_NONE && find_ret.vspace_root.unwrap() == pte_ptr {
            debug!("RISCVPageTableUnmap: cannot call unmap on top level PageTable");
            unsafe { current_syscall_error._type = seL4_RevokeFirst; }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        } else {
            unsafe { current_lookup_fault = find_ret.lookup_fault.unwrap(); }
        }
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    return invoke_page_table_unmap(cap);
}

fn decode_page_table_map(length: usize, pt_cte: &mut cte_t, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    if unlikely(length < 2 || get_extra_cap_by_index(0).is_none()) {
        debug!("RISCVPageTableMap: truncated message");
        unsafe { current_syscall_error._type = seL4_TruncatedMessage; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let cap = &mut pt_cte.cap;
    if unlikely(cap.get_pt_is_mapped() != 0) {
        debug!("RISCVPageTable: PageTable is already mapped.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 0;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let vaddr = get_syscall_arg(0, buffer);
    if unlikely(vaddr >= USER_TOP) {
        debug!("RISCVPageTableMap: Virtual address cannot be in kernel window.");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidCapNumber = 0;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;

    }
    let lvl1pt_cap = get_extra_cap_by_index(0).unwrap().cap;
    if lvl1pt_cap.get_cap_type() != CapTag::CapPageTableCap || lvl1pt_cap.get_pt_is_mapped() == asidInvalid {
        debug!("RISCVPageTableMap: Invalid top-level PageTable.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR; 
    }
    let lvl1pt = convert_to_mut_type_ref::<pte_t>(lvl1pt_cap.get_pt_base_ptr());
    let asid = lvl1pt_cap.get_pt_mapped_asid();
    
    let find_ret = find_vspace_for_asid(asid);
    if find_ret.status != exception_t::EXCEPTION_NONE {
        debug!("RISCVPageTableMap: ASID lookup failed");
        unsafe {
            current_lookup_fault = find_ret.lookup_fault.unwrap();
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 0;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if find_ret.vspace_root.unwrap() as usize != lvl1pt.get_ptr() {
        debug!("RISCVPageTableMap: ASID lookup failed");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let lu_ret = lvl1pt.lookup_pt_slot(vaddr);
    let lu_slot = convert_to_mut_type_ref::<pte_t>(lu_ret.ptSlot as usize);
    if lu_ret.ptBitsLeft == seL4_PageBits || lu_slot.get_vaild() != 0 {
        debug!("RISCVPageTableMap: All objects mapped at this address");
        unsafe { current_syscall_error._type = seL4_DeleteFirst; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    return invoke_page_table_map(cap, lu_slot, asid, vaddr & !MASK!(lu_ret.ptBitsLeft));
}