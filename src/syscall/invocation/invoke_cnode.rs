use log::debug;
use sel4_common::{
    sel4_config::{seL4_DeleteFirst, seL4_IllegalOperation, tcbCaller},
    structures::exception_t,
    utils::convert_to_mut_type_ref,
};
use sel4_cspace::interface::{
    cap_t, cte_insert, cte_move, cte_swap, cte_t, seL4_CapRights_t, CapTag,
};
use sel4_ipc::endpoint_t;
use sel4_task::{get_currenct_thread, set_thread_state, ThreadState};

use crate::{kernel::boot::current_syscall_error, syscall::mask_cap_rights};

#[inline]
pub fn invoke_cnode_copy(
    src_slot: &mut cte_t,
    dest_slot: &mut cte_t,
    cap_right: seL4_CapRights_t,
) -> exception_t {
    let src_cap = mask_cap_rights(cap_right, &src_slot.cap);
    let dc_ret = src_slot.derive_cap(&src_cap);
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        debug!("Error deriving cap for CNode Copy operation.");
        return dc_ret.status;
    }
    if dc_ret.cap.get_cap_type() == CapTag::CapNullCap {
        debug!("CNode Copy:Copy cap would be invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    cte_insert(&dc_ret.cap, src_slot, dest_slot);

    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_cnode_mint(
    src_slot: &mut cte_t,
    dest_slot: &mut cte_t,
    cap_right: seL4_CapRights_t,
    cap_data: usize,
) -> exception_t {
    let src_cap = mask_cap_rights(cap_right, &src_slot.cap);
    let new_cap = src_cap.update_data(false, cap_data);
    let dc_ret = src_slot.derive_cap(&new_cap);
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        debug!("Error deriving cap for CNode Copy operation.");
        return dc_ret.status;
    }
    if dc_ret.cap.get_cap_type() == CapTag::CapNullCap {
        debug!("CNode Mint:Mint cap would be invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    cte_insert(&dc_ret.cap, src_slot, dest_slot);

    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_cnode_mutate(
    src_slot: &mut cte_t,
    dest_slot: &mut cte_t,
    cap_data: usize,
) -> exception_t {
    let new_cap = src_slot.cap.update_data(true, cap_data);
    if new_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("CNode Mint:Mint cap would be invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    cte_move(&new_cap, src_slot, dest_slot);
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_cnode_save_caller(dest_slot: &mut cte_t) -> exception_t {
    if dest_slot.cap.get_cap_type() != CapTag::CapNullCap {
        debug!("CNode SaveCaller: Destination slot not empty.");
        unsafe {
            current_syscall_error._type = seL4_DeleteFirst;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    let src_slot = get_currenct_thread().get_cspace_mut_ref(tcbCaller);
    let cap = src_slot.cap;
    match cap.get_cap_type() {
        CapTag::CapNullCap => debug!("CNode SaveCaller: Reply cap not present."),
        CapTag::CapReplyCap => {
            if cap.get_reply_master() == 0 {
                cte_move(&cap, src_slot, dest_slot);
            }
        }
        _ => panic!("caller capability must be null or reply"),
    }
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_cnode_rotate(
    slot1: &mut cte_t,
    slot2: &mut cte_t,
    slot3: &mut cte_t,
    src_new_data: usize,
    pivot_new_data: usize,
) -> exception_t {
    let new_src_cap = slot1.cap.update_data(true, src_new_data);
    let new_pivot_cap = slot2.cap.update_data(true, pivot_new_data);

    if new_src_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("CNode Rotate: Source cap invalid");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if new_pivot_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("CNode Rotate: Pivot cap invalid");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);

    if slot1.get_ptr() == slot3.get_ptr() {
        cte_swap(&new_src_cap, slot1, &new_pivot_cap, slot2);
    } else {
        cte_move(&new_pivot_cap, slot2, slot3);
        cte_move(&new_src_cap, slot1, slot2);
    }

    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_cnode_move(src_slot: &mut cte_t, dest_slot: &mut cte_t) -> exception_t {
    let src_cap = src_slot.cap;
    if src_cap.get_cap_type() == CapTag::CapNullCap {
        debug!("CNode Copy/Mint/Move/Mutate: Mutated cap would be invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    cte_move(&src_cap, src_slot, dest_slot);
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_cnode_cancel_badged_sends(dest_slot: &mut cte_t) -> exception_t {
    let dest_cap: cap_t = dest_slot.cap;
    if !hasCancelSendRight(&dest_cap) {
        debug!("CNode CancelBadgedSends: Target cap invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    let badge = dest_cap.get_ep_badge();
    if badge != 0 {
        convert_to_mut_type_ref::<endpoint_t>(dest_cap.get_ep_ptr()).cancel_badged_sends(badge);
    }
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_cnode_revoke(dest_slot: &mut cte_t) -> exception_t {
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    dest_slot.revoke()
}

#[inline]
pub fn invoke_cnode_delete(dest_slot: &mut cte_t) -> exception_t {
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    dest_slot.delete_all(true)
}

fn hasCancelSendRight(cap: &cap_t) -> bool {
    match cap.get_cap_type() {
        CapTag::CapEndpointCap => {
            cap.get_ep_can_send() != 0
                && cap.get_ep_can_receive() != 0
                && cap.get_ep_can_grant() != 0
                && cap.get_ep_can_grant_reply() != 0
        }
        _ => false,
    }
}
