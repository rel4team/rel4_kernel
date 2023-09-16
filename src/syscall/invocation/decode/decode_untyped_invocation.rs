use common::{message_info::MessageLabel, sel4_config::{seL4_IllegalOperation, seL4_TruncatedMessage, seL4_InvalidArgument, seL4_MaxUntypedBits, wordBits, seL4_RangeError, seL4_MinUntypedBits, seL4_FailedLookup, seL4_RevokeFirst, seL4_NotEnoughMemory}, structures::{exception_t, lookup_fault_missing_capability_new, seL4_IPCBuffer}, object::{seL4_ObjectTypeCount, getObjectSize, seL4_CapTableObject, seL4_UntypedObject, ObjectType}, BIT};
use cspace::{interface::{cap_t, cte_t}, compatibility::{cap_get_capType, cap_cnode_cap_get_capCNodeRadix, cap_cnode_cap, cap_cnode_cap_get_capCNodePtr, ensureNoChildren, cap_untyped_cap_get_capFreeIndex, cap_untyped_cap_get_capPtr, cap_untyped_cap_get_capBlockSize, cap_untyped_cap_get_capIsDevice}};
use log::debug;
use task_manager::{setThreadState, ksCurThread, ThreadStateRestart};

use crate::{kernel::{boot::{current_syscall_error, current_extra_caps, current_lookup_fault, get_extra_cap_by_index}, cspace::rust_lookupTargetSlot}, syscall::{getSyscallArg, ensureEmptySlot, invocation::invoke_untyped::invokeUntyped_Retype, get_syscall_arg}, config::CONFIG_RETYPE_FAN_OUT_LIMIT, object::{untyped::{GET_FREE_REF, FREE_INDEX_TO_OFFSET, alignUp}, objecttype::Arch_isFrameType}};


pub fn decode_untyed_invocation(inv_label: MessageLabel, length: usize, slot: &mut cte_t, cap: &cap_t, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    if inv_label != MessageLabel::UntypedRetype {
        debug!("Untyped cap: Illegal operation attempted.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if length < 6 || get_extra_cap_by_index(0).is_none() {
        debug!("Untyped invocation: Truncated message.");
        unsafe { current_syscall_error._type = seL4_TruncatedMessage; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let new_type = ObjectType::from_usize(get_syscall_arg(0, buffer));
    let user_obj_size = get_syscall_arg(1, buffer);
    let node_index = get_syscall_arg(2, buffer);
    let node_depth = get_syscall_arg(3, buffer);
    let node_offset = get_syscall_arg(4, buffer);
    let node_window = get_syscall_arg(5, buffer);

    // let newType = getSyscallArg(0, buffer);
    // let userObjSize = getSyscallArg(1, buffer);
    // let nodeIndex = getSyscallArg(2, buffer);
    // let nodeDepth = getSyscallArg(3, buffer);
    // let nodeOffset = getSyscallArg(4, buffer);
    // let nodeWindow = getSyscallArg(5, buffer);

    // let _rootSlot = unsafe { current_extra_caps.excaprefs[0] };

    // if newType >= seL4_ObjectTypeCount {
    //     debug!("Untyped Retype: Invalid object type.");
    //     unsafe {
    //         current_syscall_error._type = seL4_InvalidArgument;
    //         current_syscall_error.invalidArgumentNumber = 0;
    //         return exception_t::EXCEPTION_SYSCALL_ERROR;
    //     }
    // }

}

#[no_mangle]
pub fn decodeUntypedInvocation(
    invLabel: MessageLabel,
    length: usize,
    slot: *mut cte_t,
    cap: &cap_t,
    _call: bool,
    buffer: *mut usize,
) -> exception_t {
    if invLabel != MessageLabel::UntypedRetype {
        debug!("Untyped cap: Illegal operation attempted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        if length < 6 || current_extra_caps.excaprefs[0] as usize == 0 {
            debug!("Untyped invocation: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let newType = getSyscallArg(0, buffer);
    let userObjSize = getSyscallArg(1, buffer);
    let nodeIndex = getSyscallArg(2, buffer);
    let nodeDepth = getSyscallArg(3, buffer);
    let nodeOffset = getSyscallArg(4, buffer);
    let nodeWindow = getSyscallArg(5, buffer);

    let _rootSlot = unsafe { current_extra_caps.excaprefs[0] };

    if newType >= seL4_ObjectTypeCount {
        debug!("Untyped Retype: Invalid object type.");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 0;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let objectSize = getObjectSize(newType, userObjSize);

    if userObjSize >= wordBits || objectSize > seL4_MaxUntypedBits {
        unsafe {
            debug!("Untyped Retype: Invalid object size.");
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 0;
            current_syscall_error.rangeErrorMax = seL4_MaxUntypedBits;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if newType == seL4_CapTableObject && userObjSize == 0 {
        unsafe {
            debug!("Untyped Retype: Requested CapTable size too small.");
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if newType == seL4_UntypedObject && userObjSize < seL4_MinUntypedBits {
        unsafe {
            debug!("Untyped Retype: Requested UntypedItem size too small.");
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let nodeCap: cap_t;
    if nodeDepth == 0 {
        nodeCap = unsafe { (*current_extra_caps.excaprefs[0]).cap.clone() };
    } else {
        let rootCap = unsafe { (*current_extra_caps.excaprefs[0]).cap.clone() };
        let lu_ret = rust_lookupTargetSlot(&rootCap, nodeIndex, nodeDepth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            debug!("Untyped Retype: Invalid destination address.");
            return lu_ret.status;
        }
        nodeCap = unsafe { (*lu_ret.slot).cap.clone() };
    }

    if cap_get_capType(&nodeCap) != cap_cnode_cap {
        debug!("Untyped Retype: Destination cap invalid or read-only.");
        unsafe {
            current_syscall_error._type = seL4_FailedLookup;
            current_syscall_error.failedLookupWasSource = 0;
            current_lookup_fault = lookup_fault_missing_capability_new(nodeDepth);
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let nodeSize = 1 << cap_cnode_cap_get_capCNodeRadix(&nodeCap);

    if nodeOffset > (nodeSize - 1) {
        unsafe {
            debug!(
                "Untyped Retype: Destination node offset {} too large.",
                nodeOffset
            );
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 0;
            current_syscall_error.rangeErrorMax = nodeSize - 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if nodeWindow < 1 || nodeWindow > CONFIG_RETYPE_FAN_OUT_LIMIT {
        unsafe {
            debug!(
                "Untyped Retype: Number of requested objects {} too small or large.",
                nodeWindow
            );
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = CONFIG_RETYPE_FAN_OUT_LIMIT;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if nodeWindow > nodeSize - nodeOffset {
        unsafe {
            debug!("Untyped Retype: Requested destination window overruns size of node.");
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = nodeSize - nodeOffset;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let destCNode = cap_cnode_cap_get_capCNodePtr(&nodeCap) as *mut cte_t;
    for i in nodeOffset..(nodeOffset + nodeWindow) {
        let status = unsafe { ensureEmptySlot(destCNode.add(i)) };
        if status != exception_t::EXCEPTION_NONE {
            debug!(
                "Untyped Retype: Slot {:#x} in destination window non-empty.",
                i
            );
            return status;
        }
    }

    let status = ensureNoChildren(slot);
    let freeIndex: usize;
    let reset: bool;
    if status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_syscall_error._type = seL4_RevokeFirst;
        }
        freeIndex = cap_untyped_cap_get_capFreeIndex(cap);
        reset = false;
    } else {
        freeIndex = 0;
        reset = true;
    }
    let freeRef = GET_FREE_REF(cap_untyped_cap_get_capPtr(cap), freeIndex);

    let untypedFreeBytes =
        BIT!(cap_untyped_cap_get_capBlockSize(cap)) - FREE_INDEX_TO_OFFSET(freeIndex);

    if (untypedFreeBytes >> objectSize) < nodeWindow {
        debug!(
            "Untyped Retype: Insufficient memory 
                      ({} * {} bytes needed, {} bytes available).",
            nodeWindow,
            if objectSize >= wordBits {
                -1
            } else {
                1 << objectSize
            },
            untypedFreeBytes
        );
        unsafe {
            current_syscall_error._type = seL4_NotEnoughMemory;
            current_syscall_error.memoryLeft = untypedFreeBytes;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let deviceMemory = cap_untyped_cap_get_capIsDevice(cap) != 0;
    if deviceMemory && !Arch_isFrameType(newType) && newType != seL4_UntypedObject {
        debug!("Untyped Retype: Creating kernel objects with device untyped");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let alignedFreeRef = alignUp(freeRef, objectSize) as *mut usize;
    unsafe {
        setThreadState(ksCurThread, ThreadStateRestart);
    }
    invokeUntyped_Retype(
        slot,
        reset,
        alignedFreeRef,
        newType,
        userObjSize,
        destCNode,
        nodeOffset,
        nodeWindow,
        deviceMemory,
    )
}
