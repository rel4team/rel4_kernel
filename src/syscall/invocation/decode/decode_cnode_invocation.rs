use log::debug;
use sel4_common::fault::lookup_fault_t;
use sel4_common::{
    message_info::MessageLabel,
    sel4_config::{
        seL4_DeleteFirst, seL4_FailedLookup, seL4_IllegalOperation, seL4_TruncatedMessage,
    },
    structures::{exception_t, seL4_IPCBuffer},
    utils::convert_to_mut_type_ref,
};
use sel4_cspace::interface::{cap_t, cte_t, seL4_CapRights_t, CapTag};

use crate::{
    kernel::boot::{current_lookup_fault, current_syscall_error, get_extra_cap_by_index},
    syscall::{get_syscall_arg, invocation::invoke_cnode::*, lookup_slot_for_cnode_op},
};

pub fn decode_cnode_invocation(
    invLabel: MessageLabel,
    length: usize,
    cap: &cap_t,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if invLabel < MessageLabel::CNodeRevoke || invLabel > MessageLabel::CNodeSaveCaller {
        debug!("CNodeCap: Illegal Operation attempted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if length < 2 {
        debug!("CNode operation: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let index = get_syscall_arg(0, buffer);
    let w_bits = get_syscall_arg(1, buffer);
    let lu_ret = lookup_slot_for_cnode_op(false, cap, index, w_bits);

    if lu_ret.status != exception_t::EXCEPTION_NONE {
        debug!("CNode operation: Target slot invalid.");
        return lu_ret.status;
    }
    let dest_slot = convert_to_mut_type_ref::<cte_t>(lu_ret.slot as usize);
    match invLabel {
        MessageLabel::CNodeCopy
        | MessageLabel::CNodeMint
        | MessageLabel::CNodeMove
        | MessageLabel::CNodeMutate => {
            return decode_cnode_invoke_with_two_slot(invLabel, dest_slot, length, buffer);
        }
        MessageLabel::CNodeRevoke => invoke_cnode_revoke(dest_slot),
        MessageLabel::CNodeDelete => invoke_cnode_delete(dest_slot),
        MessageLabel::CNodeSaveCaller => invoke_cnode_save_caller(dest_slot),
        MessageLabel::CNodeCancelBadgedSends => invoke_cnode_cancel_badged_sends(dest_slot),
        MessageLabel::CNodeRotate => decode_cnode_rotate(dest_slot, length, buffer),
        _ => panic!("invalid invlabel: {:?}", invLabel),
    }
}

fn decode_cnode_invoke_with_two_slot(
    label: MessageLabel,
    dest_slot: &mut cte_t,
    length: usize,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if length < 4 || get_extra_cap_by_index(0).is_none() {
        debug!("CNode Copy/Mint/Move/Mutate: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let src_index = get_syscall_arg(2, buffer);
    let src_depth = get_syscall_arg(3, buffer);
    let src_root = get_extra_cap_by_index(0).unwrap().cap;
    if dest_slot.cap.get_cap_type() != CapTag::CapNullCap {
        debug!("CNode Copy/Mint/Move/Mutate: Destination not empty.");
        unsafe {
            current_syscall_error._type = seL4_DeleteFirst;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let lu_ret = lookup_slot_for_cnode_op(true, &src_root, src_index, src_depth);
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        debug!("CNode Copy/Mint/Move/Mutate: Invalid source slot.");
        return lu_ret.status;
    }
    let src_slot = convert_to_mut_type_ref::<cte_t>(lu_ret.slot as usize);
    if src_slot.cap.get_cap_type() == CapTag::CapNullCap {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 1;
            current_lookup_fault = lookup_fault_t::new_missing_cap(src_depth);
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    match label {
        MessageLabel::CNodeCopy => {
            if length < 5 {
                debug!("Truncated message for CNode Copy operation.");
                unsafe {
                    current_syscall_error._type = seL4_TruncatedMessage;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let cap_right = seL4_CapRights_t::from_word(get_syscall_arg(4, buffer));
            return invoke_cnode_copy(src_slot, dest_slot, cap_right);
        }

        MessageLabel::CNodeMint => {
            if length < 6 {
                debug!("Truncated message for CNode Mint operation.");
                unsafe {
                    current_syscall_error._type = seL4_TruncatedMessage;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let cap_right = seL4_CapRights_t::from_word(get_syscall_arg(4, buffer));
            let cap_data = get_syscall_arg(5, buffer);
            return invoke_cnode_mint(src_slot, dest_slot, cap_right, cap_data);
        }

        MessageLabel::CNodeMove => {
            return invoke_cnode_move(src_slot, dest_slot);
        }

        MessageLabel::CNodeMutate => {
            if length < 5 {
                debug!("Truncated message for CNode Mutate operation.");
                unsafe {
                    current_syscall_error._type = seL4_TruncatedMessage;
                }
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
            let cap_data = get_syscall_arg(4, buffer);
            return invoke_cnode_mutate(src_slot, dest_slot, cap_data);
        }
        _ => {
            panic!("invalid invLabel:{:?}", label);
        }
    }
}

fn decode_cnode_rotate(
    dest_slot: &mut cte_t,
    length: usize,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if length < 8 || get_extra_cap_by_index(0).is_none() || get_extra_cap_by_index(1).is_none() {
        debug!("CNode Rotate: Target cap invalid.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let pivot_new_data = get_syscall_arg(2, buffer);
    let pivot_index = get_syscall_arg(3, buffer);
    let pivot_depth = get_syscall_arg(4, buffer);
    let src_new_data = get_syscall_arg(5, buffer);
    let src_idnex = get_syscall_arg(6, buffer);
    let src_depth = get_syscall_arg(7, buffer);

    let pivot_root = get_extra_cap_by_index(0).unwrap().cap;
    let src_root = get_extra_cap_by_index(1).unwrap().cap;

    let lu_ret = lookup_slot_for_cnode_op(true, &src_root, src_idnex, src_depth);
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        return lu_ret.status;
    }
    let src_slot = convert_to_mut_type_ref::<cte_t>(lu_ret.slot as usize);

    let lu_ret = lookup_slot_for_cnode_op(true, &pivot_root, pivot_index, pivot_depth);
    if lu_ret.status != exception_t::EXCEPTION_NONE {
        return lu_ret.status;
    }
    let pivot_slot = convert_to_mut_type_ref::<cte_t>(lu_ret.slot as usize);

    if pivot_slot.get_ptr() == src_slot.get_ptr() || pivot_slot.get_ptr() == dest_slot.get_ptr() {
        debug!("CNode Rotate: Pivot slot the same as source or dest slot.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    if src_slot.get_ptr() != dest_slot.get_ptr() {
        if dest_slot.cap.get_cap_type() != CapTag::CapNullCap {
            unsafe {
                current_syscall_error._type = seL4_DeleteFirst;
            }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if src_slot.cap.get_cap_type() == CapTag::CapNullCap {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 1;
            current_lookup_fault = lookup_fault_t::new_missing_cap(src_depth);
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if pivot_slot.cap.get_cap_type() == CapTag::CapNullCap {
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 0;
            current_lookup_fault = lookup_fault_t::new_missing_cap(pivot_depth);
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    return invoke_cnode_rotate(
        src_slot,
        pivot_slot,
        dest_slot,
        src_new_data,
        pivot_new_data,
    );
}
