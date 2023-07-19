use crate::{
    config::{
        seL4_CapTableObject, seL4_FailedLookup, seL4_IllegalOperation, seL4_InvalidArgument,
        seL4_NotEnoughMemory, seL4_ObjectTypeCount, seL4_RangeError, seL4_TruncatedMessage,
        seL4_UntypedObject, ThreadStateRestart, UntypedRetype, CONFIG_RESET_CHUNK_BITS,
        CONFIG_RETYPE_FAN_OUT_LIMIT, seL4_RevokeFirst,
    },
    kernel::{
        boot::{current_extra_caps, current_lookup_fault, current_syscall_error},
        cspace::rust_lookupTargetSlot,
        thread::{ksCurThread, setThreadState},
    },
    object::structure_gen::lookup_fault_missing_capability_new,
    println,
    syscall::getSyscallArg,
    BIT, MASK, ROUND_DOWN, boot::clearMemory,
};

use super::{
    cap::{ensureEmptySlot},
    objecttype::{
        createNewObjects, getObjectSize, Arch_isFrameType,
    },
};

use common::{structures::exception_t, sel4_config::*};
use cspace::interface::*;

pub fn alignUp(baseValue: usize, alignment: usize) -> usize {
    (baseValue + BIT!(alignment) - 1) & !MASK!(alignment)
}

pub fn FREE_INDEX_TO_OFFSET(freeIndex: usize) -> usize {
    freeIndex << seL4_MinUntypedBits
}
pub fn GET_FREE_REF(base: usize, freeIndex: usize) -> usize {
    base + FREE_INDEX_TO_OFFSET(freeIndex)
}
pub fn GET_FREE_INDEX(base: usize, free: usize) -> usize {
    free - base >> seL4_MinUntypedBits
}
pub fn GET_OFFSET_FREE_PTR(base: usize, offset: usize) -> *mut usize {
    (base + offset) as *mut usize
}
pub fn OFFSET_TO_FREE_IDNEX(offset: usize) -> usize {
    offset >> seL4_MinUntypedBits
}

#[no_mangle]
pub fn resetUntypedCap(srcSlot: *mut cte_t) -> exception_t {
    unsafe {
        let prev_cap = &mut (*srcSlot).cap;
        let block_size = cap_untyped_cap_get_capBlockSize(prev_cap);
        let regionBase = cap_untyped_cap_get_capPtr(prev_cap);
        let chunk = CONFIG_RESET_CHUNK_BITS;
        let offset = FREE_INDEX_TO_OFFSET(cap_untyped_cap_get_capFreeIndex(prev_cap));
        let deviceMemory = cap_untyped_cap_get_capIsDevice(prev_cap);
        if offset == 0 {
            return exception_t::EXCEPTION_NONE;
        }

        if deviceMemory != 0 && block_size < chunk {
            if deviceMemory != 0 {
                clearMemory(regionBase as *mut u8, block_size);
            }
            cap_untyped_cap_set_capFreeIndex(prev_cap, 0);
        } else {
            let mut offset: isize = ROUND_DOWN!(offset - 1, chunk) as isize;
            while offset != -(BIT!(chunk) as isize) {
                clearMemory(
                    GET_OFFSET_FREE_PTR(regionBase, offset as usize) as *mut u8,
                    chunk,
                );
                offset -= BIT!(chunk) as isize;
            }
            cap_untyped_cap_set_capFreeIndex(prev_cap, OFFSET_TO_FREE_IDNEX(offset as usize));
        }
        exception_t::EXCEPTION_NONE
    }
}

#[no_mangle]
pub fn invokeUntyped_Retype(
    srcSlot: *mut cte_t,
    reset: bool,
    retypeBase: *mut usize,
    newType: usize,
    userSize: usize,
    destCNode: *mut cte_t,
    destOffset: usize,
    destLength: usize,
    deviceMemory: bool,
) -> exception_t {
    let regionBase = unsafe { cap_untyped_cap_get_capPtr(&(*srcSlot).cap) as *mut usize };
    if reset {
        let status = resetUntypedCap(srcSlot);
        if status != exception_t::EXCEPTION_NONE {
            return status;
        }
    }
    let totalObjectSize = destLength << getObjectSize(newType, userSize);
    let freeRef = retypeBase as usize + totalObjectSize;
    unsafe {
        cap_untyped_cap_set_capFreeIndex(
            &mut (*srcSlot).cap,
            GET_FREE_INDEX(regionBase as usize, freeRef),
        );
    }
    createNewObjects(
        newType,
        srcSlot,
        destCNode,
        destOffset,
        destLength,
        retypeBase,
        userSize,
        deviceMemory,
    );
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn decodeUntypedInvocation(
    invLabel: usize,
    length: usize,
    slot: *mut cte_t,
    cap: &cap_t,
    _call: bool,
    buffer: *mut usize,
) -> exception_t {
    if invLabel != UntypedRetype {
        println!("Untyped cap: Illegal operation attempted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    unsafe {
        if length < 6 || current_extra_caps.excaprefs[0] as usize == 0 {
            println!("Untyped invocation: Truncated message.");
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
        println!("Untyped Retype: Invalid object type.");
        unsafe {
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 0;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    let objectSize = getObjectSize(newType, userObjSize);

    if userObjSize >= wordBits || objectSize > seL4_MaxUntypedBits {
        unsafe {
            println!("Untyped Retype: Invalid object size.");
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 0;
            current_syscall_error.rangeErrorMax = seL4_MaxUntypedBits;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if newType == seL4_CapTableObject && userObjSize == 0 {
        unsafe {
            println!("Untyped Retype: Requested CapTable size too small.");
            current_syscall_error._type = seL4_InvalidArgument;
            current_syscall_error.invalidArgumentNumber = 1;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }

    if newType == seL4_UntypedObject && userObjSize < seL4_MinUntypedBits {
        unsafe {
            println!("Untyped Retype: Requested UntypedItem size too small.");
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
            println!("Untyped Retype: Invalid destination address.");
            return lu_ret.status;
        }
        nodeCap = unsafe { (*lu_ret.slot).cap.clone() };
    }

    if cap_get_capType(&nodeCap) != cap_cnode_cap {
        println!("Untyped Retype: Destination cap invalid or read-only.");
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
            println!(
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
            println!(
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
            println!("Untyped Retype: Requested destination window overruns size of node.");
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
            println!(
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
        println!(
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
        println!("Untyped Retype: Creating kernel objects with device untyped");
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
