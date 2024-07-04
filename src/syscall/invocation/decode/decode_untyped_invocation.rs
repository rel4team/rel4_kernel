use crate::BIT;
use log::debug;
use sel4_common::fault::lookup_fault_t;
use sel4_common::{
    message_info::MessageLabel, object::ObjectType, sel4_config::*, structures::*,
    utils::convert_to_mut_type_ref,
};
use sel4_cspace::interface::{cap_t, cte_t, CapTag};
use sel4_task::{get_currenct_thread, set_thread_state, ThreadState};

use crate::syscall::{alignUp, FREE_INDEX_TO_OFFSET, GET_FREE_REF};
use crate::{
    config::CONFIG_RETYPE_FAN_OUT_LIMIT,
    kernel::boot::{current_lookup_fault, current_syscall_error, get_extra_cap_by_index},
    syscall::{
        get_syscall_arg, invocation::invoke_untyped::invoke_untyped_retype,
        lookup_slot_for_cnode_op,
    },
};

pub fn decode_untyed_invocation(
    inv_label: MessageLabel,
    length: usize,
    slot: &mut cte_t,
    cap: &cap_t,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if inv_label != MessageLabel::UntypedRetype {
        debug!("Untyped cap: Illegal operation attempted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if length < 6 || get_extra_cap_by_index(0).is_none() {
        debug!("Untyped invocation: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let op_new_type = ObjectType::from_usize(get_syscall_arg(0, buffer));
    if op_new_type.is_none() {
        debug!(
            "Untyped Retype: Invalid object type. {}",
            get_syscall_arg(0, buffer)
        );
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 0;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let new_type = op_new_type.unwrap();
    let user_obj_size = get_syscall_arg(1, buffer);
    let node_index = get_syscall_arg(2, buffer);
    let node_depth = get_syscall_arg(3, buffer);
    let node_offset = get_syscall_arg(4, buffer);
    let node_window = get_syscall_arg(5, buffer);
    let obj_size = new_type.get_object_size(user_obj_size);
    if user_obj_size >= wordBits || obj_size > seL4_MaxUntypedBits {
        debug!(
            "Untyped Retype: Invalid object size. {} : {}",
            user_obj_size, obj_size
        );
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 0;
            current_syscall_error.rangeErrorMax = seL4_MaxUntypedBits;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let status = check_object_type(new_type, user_obj_size);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }
    let mut node_cap = cap_t::default();
    let status = get_target_cnode(node_index, node_depth, &mut node_cap);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }

    let status = check_cnode_slot(&node_cap, node_offset, node_window);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }

    let status = slot.ensure_no_children();
    let (free_index, reset) = if status != exception_t::EXCEPTION_NONE {
        // 原始 untype 有子节点
        unsafe {
            current_syscall_error._type = seL4_RevokeFirst;
        }
        (cap.get_untyped_free_index(), false)
    } else {
        (0, true)
    };

    let free_ref = GET_FREE_REF(cap.get_untyped_ptr(), free_index);
    let untyped_free_bytes = BIT!(cap.get_untyped_block_size()) - FREE_INDEX_TO_OFFSET(free_index);

    if (untyped_free_bytes >> obj_size) < node_window {
        debug!(
            "Untyped Retype: Insufficient memory({} * {} bytes needed, {} bytes available)",
            node_window,
            if obj_size >= wordBits {
                -1
            } else {
                1i64 << obj_size
            },
            untyped_free_bytes
        );
        unsafe {
            current_syscall_error._type = seL4_NotEnoughMemory;
            current_syscall_error.memoryLeft = untyped_free_bytes;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let device_mem = cap.get_frame_is_device() != 0;
    if device_mem && new_type.is_arch_type() && new_type != ObjectType::UnytpedObject {
        debug!("Untyped Retype: Creating kernel objects with device untyped");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let aligned_free_ref = alignUp(free_ref, obj_size);

    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_untyped_retype(
        slot,
        reset,
        aligned_free_ref,
        new_type,
        user_obj_size,
        convert_to_mut_type_ref::<cte_t>(node_cap.get_cnode_ptr()),
        node_offset,
        node_window,
        device_mem as usize,
    )
}

#[inline]
fn check_object_type(new_type: ObjectType, user_obj_size: usize) -> exception_t {
    if new_type == ObjectType::CapTableObject && user_obj_size == 0 {
        debug!("Untyped Retype: Requested CapTable size too small.");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if new_type == ObjectType::UnytpedObject && user_obj_size < seL4_MinUntypedBits {
        debug!("Untyped Retype: Requested UntypedItem size too small.");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    return exception_t::EXCEPTION_NONE;
}

#[inline]
fn get_target_cnode(node_index: usize, node_depth: usize, node_cap: &mut cap_t) -> exception_t {
    let target_node_cap = if node_depth == 0 {
        get_extra_cap_by_index(0).unwrap().cap
    } else {
        let root_cap = get_extra_cap_by_index(0).unwrap().cap;
        let lu_ret = lookup_slot_for_cnode_op(false, &root_cap, node_index, node_depth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            debug!("Untyped Retype: Invalid destination address.");
            return lu_ret.status;
        }
        unsafe { (*lu_ret.slot).cap }
    };

    if target_node_cap.get_cap_type() != CapTag::CapCNodeCap {
        debug!("Untyped Retype: Destination cap invalid or read-only.");
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 0;
            current_lookup_fault = lookup_fault_t::new_missing_cap(node_depth);
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    *node_cap = target_node_cap;
    exception_t::EXCEPTION_NONE
}

#[inline]
fn check_cnode_slot(node_cap: &cap_t, node_offset: usize, node_window: usize) -> exception_t {
    let node_size = 1 << node_cap.get_cnode_radix();
    if node_offset > (node_size - 1) {
        debug!(
            "Untyped Retype: Destination node offset {} too large.",
            node_offset
        );
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 0;
            current_syscall_error.rangeErrorMax = node_size - 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if node_window < 1 || node_window > CONFIG_RETYPE_FAN_OUT_LIMIT {
        debug!(
            "Untyped Retype: Number of requested objects {} too small or large.",
            node_window
        );
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = CONFIG_RETYPE_FAN_OUT_LIMIT;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if node_window > node_size - node_offset {
        debug!("Untyped Retype: Requested destination window overruns size of node.");
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = node_size - node_offset;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let dest_cnode = convert_to_mut_type_ref::<cte_t>(node_cap.get_cnode_ptr());
    for i in node_offset..(node_offset + node_window) {
        if dest_cnode.get_offset_slot(i).cap.get_cap_type() != CapTag::CapNullCap {
            debug!(
                "Untyped Retype: Slot {:#x} in destination window non-empty.",
                i
            );
            unsafe {
                current_syscall_error._type = seL4_DeleteFirst;
            }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    exception_t::EXCEPTION_NONE
}
