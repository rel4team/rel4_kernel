use core::intrinsics::unlikely;

use crate::{
    config::{
        seL4_CapTableObject, seL4_EndpointObject, seL4_HugePageBits,
        seL4_InvalidCapability, seL4_LargePageBits, seL4_NotificationObject,
        seL4_TCBBits, seL4_TCBObject, seL4_UntypedObject,
        tcbCNodeEntries, tcbCTable, IRQInactive, ThreadStateRestart, CONFIG_TIME_SLICE, TCB_OFFSET,
    },
    kernel::{
        boot::{current_syscall_error, current_lookup_fault},
        thread::{
            decodeDomainInvocation, doReplyTransfer,
            setThreadState, suspend, Arch_initContext,
        },
        transfermsg::{
            seL4_CNode_capData_get_guard, seL4_CNode_capData_get_guardSize, vmRighsFromWord,
            wordFromVMRights,
        },
        vspace::{
            decodeRISCVMMUInvocation, deleteASID, deleteASIDPool,
        },
    },
    structures::{
        endpoint_t, finaliseCap_ret,
        notification_t, seL4_CNode_CapData_t,
    },
};

use crate::task_manager::*;
use log::debug;
use vspace::*;

use super::{
    cap::decodeCNodeInvocation,
    endpoint::{cancelAllIPC, performInvocation_Endpoint},
    interrupt::{
        decodeIRQControlInvocation, decodeIRQHandlerInvocation, deletingIRQHandler, setIRQState,
    },
    notification::{
        cancelAllSignals, performInvocation_Notification, unbindMaybeNotification,
        unbindNotification,
    },
    tcb::decodeTCBInvocation,
    untyped::decodeUntypedInvocation,
};

use common::{structures::exception_t, sel4_config::*, MASK};
use cspace::interface::*;


pub const seL4_RISCV_Giga_Page: usize = 5;
pub const seL4_RISCV_4K_Page: usize = 6;
pub const seL4_RISCV_Mega_Page: usize = 7;
pub const seL4_RISCV_PageTableObject: usize = 8;


#[no_mangle]
pub fn Arch_finaliseCap(cap: &cap_t, _final: bool) -> finaliseCap_ret {
    let mut fc_ret = finaliseCap_ret::default();
    match cap_get_capType(cap) {
        cap_frame_cap => {
            if cap_frame_cap_get_capFMappedASID(cap) != 0 {
                match unmapPage(
                    cap_frame_cap_get_capFSize(cap),
                    cap_frame_cap_get_capFMappedASID(cap),
                    cap_frame_cap_get_capFMappedAddress(cap),
                    cap_frame_cap_get_capFBasePtr(cap),
                ) {
                    Err(lookup_fault) => {
                        unsafe {
                            current_lookup_fault = lookup_fault
                        }
                    }
                    _ => {}
                }
            }
        }
        cap_page_table_cap => {
            if _final && (cap_page_table_cap_get_capPTIsMapped(cap) != 0) {
                let asid = cap_page_table_cap_get_capPTMappedASID(cap);
                let find_ret = findVSpaceForASID(asid);
                let pte = cap_page_table_cap_get_capPTBasePtr(cap);
                if find_ret.status == exception_t::EXCEPTION_NONE
                    && find_ret.vspace_root.unwrap() as usize == pte
                {
                    deleteASID(asid, pte as *mut pte_t);
                } else {
                    unmapPageTable(
                        asid,
                        cap_page_table_cap_get_capPTMappedAddress(cap),
                        pte as *mut pte_t,
                    );
                }
                if let Some(lookup_fault) = find_ret.lookup_fault {
                    unsafe {
                        current_lookup_fault = lookup_fault;
                    }
                }
            }
        }
        cap_asid_pool_cap => {
            if _final {
                deleteASIDPool(
                    cap_asid_pool_cap_get_capASIDBase(cap),
                    cap_asid_pool_cap_get_capASIDPool(cap) as *mut asid_pool_t,
                );
            }
        }
        cap_asid_control_cap => {}
        _ => {}
    }
    fc_ret.remainder = cap_null_cap_new();
    fc_ret.cleanupInfo = cap_null_cap_new();
    fc_ret
}

#[link(name = "kernel_all.c")]
extern "C" {
    fn tcbDebugRemove(tcb: *mut tcb_t);
    fn tcbDebugAppend(tcb: *mut tcb_t);
}
#[no_mangle]
pub fn finaliseCap(cap: &cap_t, _final: bool, _exposed: bool) -> finaliseCap_ret {
    let mut fc_ret = finaliseCap_ret::default();

    if isArchCap(cap) {
        return Arch_finaliseCap(cap, _final);
    }
    match cap_get_capType(cap) {
        cap_endpoint_cap => {
            if _final {
                cancelAllIPC(cap_endpoint_cap_get_capEPPtr(cap) as *mut endpoint_t);
            }
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        cap_notification_cap => {
            if _final {
                let ntfn = cap_notification_cap_get_capNtfnPtr(cap) as *mut notification_t;
                unbindMaybeNotification(ntfn);
                cancelAllSignals(ntfn);
            }
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        cap_reply_cap | cap_null_cap | cap_domain_cap => {
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        _ => {
            if _exposed {
                panic!("finaliseCap: failed to finalise immediately.");
            }
        }
    }

    match cap_get_capType(cap) {
        cap_cnode_cap => {
            if _final {
                fc_ret.remainder = Zombie_new(
                    1usize << cap_cnode_cap_get_capCNodeRadix(cap),
                    cap_cnode_cap_get_capCNodeRadix(cap),
                    cap_cnode_cap_get_capCNodePtr(cap),
                );
                fc_ret.cleanupInfo = cap_null_cap_new();
                return fc_ret;
            } else {
                fc_ret.remainder = cap_null_cap_new();
                fc_ret.cleanupInfo = cap_null_cap_new();
                return fc_ret;
            }
        }
        cap_thread_cap => {
            if _final {
                let tcb = cap_thread_cap_get_capTCBPtr(cap) as *mut tcb_t;
                let cte_ptr = getCSpace(tcb as usize, tcbCTable) as *mut cte_t;
                unbindNotification(tcb);
                suspend(tcb);
                unsafe {
                    tcbDebugRemove(tcb);
                }
                fc_ret.remainder =
                    Zombie_new(tcbCNodeEntries, ZombieType_ZombieTCB, cte_ptr as usize);
                fc_ret.cleanupInfo = cap_null_cap_new();
                return fc_ret;
            }
        }
        cap_zombie_cap => {
            fc_ret.remainder = cap.clone();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
        cap_irq_handler_cap => {
            if _final {
                let irq = cap_irq_handler_cap_get_capIRQ(cap);
                deletingIRQHandler(irq);
                fc_ret.remainder = cap_null_cap_new();
                fc_ret.cleanupInfo = cap.clone();
                return fc_ret;
            }
        }
        _ => {
            fc_ret.remainder = cap_null_cap_new();
            fc_ret.cleanupInfo = cap_null_cap_new();
            return fc_ret;
        }
    }
    fc_ret.remainder = cap_null_cap_new();
    fc_ret.cleanupInfo = cap_null_cap_new();
    return fc_ret;
}

pub fn updateCapData(preserve: bool, newData: usize, _cap: &cap_t) -> cap_t {
    let cap = &mut (_cap.clone());
    if isArchCap(cap) {
        let val1 = cap.words[0];
        let val2 = cap.words[1];
        return cap_t {
            words: [val1, val2],
        };
    }
    match cap_get_capType(cap) {
        cap_endpoint_cap => {
            let mut new_cap = _cap.clone();
            if !preserve && (cap_endpoint_cap_get_capEPBadge(cap) == 0) {
                cap_endpoint_cap_set_capEPBadge(&mut new_cap, newData);
                return new_cap;
            } else {
                return cap_null_cap_new();
            }
        }
        cap_notification_cap => {
            let mut new_cap = _cap.clone();
            if !preserve && cap_notification_cap_get_capNtfnBadge(cap) == 0 {
                cap_notification_cap_set_capNtfnBadge(&mut new_cap, newData);
                return new_cap;
            } else {
                return cap_null_cap_new();
            }
        }
        cap_cnode_cap => {
            let w = seL4_CNode_CapData_t { words: [newData] };
            let guardSize = seL4_CNode_capData_get_guardSize(&w);

            if guardSize + cap_cnode_cap_get_capCNodeRadix(cap) > wordBits {
                return cap_null_cap_new();
            } else {
                let guard = seL4_CNode_capData_get_guard(&w) & MASK!(guardSize);
                let mut new_cap = cap.clone();
                cap_cnode_cap_set_capCNodeGuard(&mut new_cap, guard);
                cap_cnode_cap_set_capCNodeGuardSize(&mut new_cap, guardSize);
                return new_cap;
            }
        }
        _ => return cap.clone(),
    }
}

pub fn postCapDeletion(cap: &cap_t) {
    if cap_get_capType(cap) == cap_irq_handler_cap {
        let irq = cap_irq_handler_cap_get_capIRQ(cap);
        setIRQState(IRQInactive, irq);
    }
}
// #[no_mangle]
pub fn maskCapRights(rights: seL4_CapRights_t, _cap: &cap_t) -> cap_t {
    match cap_get_capType(_cap) {
        cap_null_cap | cap_domain_cap | cap_cnode_cap | cap_untyped_cap | cap_irq_control_cap
        | cap_irq_handler_cap | cap_zombie_cap | cap_thread_cap | cap_page_table_cap
        | cap_asid_control_cap | cap_asid_pool_cap => _cap.clone(),
        cap_endpoint_cap => {
            let cap = &mut _cap.clone();
            cap_endpoint_cap_set_capCanSend(
                cap,
                cap_endpoint_cap_get_capCanSend(cap) & seL4_CapRights_get_capAllowWrite(&rights),
            );
            cap_endpoint_cap_set_capCanReceive(
                cap,
                cap_endpoint_cap_get_capCanReceive(cap) & seL4_CapRights_get_capAllowRead(&rights),
            );
            cap_endpoint_cap_set_capCanGrant(
                cap,
                cap_endpoint_cap_get_capCanGrant(cap) & seL4_CapRights_get_capAllowGrant(&rights),
            );
            cap_endpoint_cap_set_capCanGrantReply(
                cap,
                cap_endpoint_cap_get_capCanGrantReply(cap)
                    & seL4_CapRights_get_capAllowGrantReply(&rights),
            );
            cap.clone()
        }
        cap_notification_cap => {
            let cap = &mut _cap.clone();
            cap_notification_cap_set_capNtfnCanSend(
                cap,
                cap_notification_cap_get_capNtfnCanSend(cap)
                    & seL4_CapRights_get_capAllowWrite(&rights),
            );
            cap_notification_cap_set_capNtfnCanReceive(
                cap,
                cap_notification_cap_get_capNtfnCanReceive(cap)
                    & seL4_CapRights_get_capAllowRead(&rights),
            );
            cap.clone()
        }
        cap_reply_cap => {
            let cap = &mut _cap.clone();
            cap_reply_cap_set_capReplyCanGrant(
                cap,
                cap_reply_cap_get_capReplyCanGrant(cap) & seL4_CapRights_get_capAllowGrant(&rights),
            );
            cap.clone()
        }
        cap_frame_cap => {
            let cap = &mut _cap.clone();
            let mut vm_rights = vmRighsFromWord(cap_frame_cap_get_capFVMRights(cap));
            vm_rights = maskVMRights(vm_rights, rights);
            cap_frame_cap_set_capFVMRights(cap, wordFromVMRights(vm_rights));
            cap.clone()
        }

        _ => panic!("Invalid cap!"),
    }
}

pub fn hasCancelSendRight(cap: &cap_t) -> bool {
    match cap_get_capType(cap) {
        cap_endpoint_cap => {
            cap_endpoint_cap_get_capCanSend(cap) != 0
                && cap_endpoint_cap_get_capCanReceive(cap) != 0
                && cap_endpoint_cap_get_capCanGrantReply(cap) != 0
                && cap_endpoint_cap_get_capCanGrant(cap) != 0
        }
        _ => false,
    }
}

#[no_mangle]
pub fn createObject(
    t: usize,
    regionBase: *mut usize,
    userSize: usize,
    deviceMemory: bool,
) -> cap_t {
    match t {
        seL4_TCBObject => {
            let tcb = (regionBase as usize + TCB_OFFSET) as *mut tcb_t;
            unsafe {
                (*tcb).tcbArch = Arch_initContext((*tcb).tcbArch);
                (*tcb).tcbTimeSlice = CONFIG_TIME_SLICE;
                (*tcb).domain = ksCurDomain;
                tcbDebugAppend(tcb);
            }
            return cap_thread_cap_new(tcb as usize);
        }
        seL4_EndpointObject => cap_endpoint_cap_new(0, 1, 1, 1, 1, regionBase as usize),
        seL4_NotificationObject => cap_notification_cap_new(0, 1, 1, regionBase as usize),
        seL4_CapTableObject => cap_cnode_cap_new(userSize, 0, 0, regionBase as usize),
        seL4_UntypedObject => {
            cap_untyped_cap_new(0, deviceMemory as usize, userSize, regionBase as usize)
        }
        seL4_RISCV_4K_Page => cap_frame_cap_new(
            asidInvalid,
            regionBase as usize,
            RISCV_4K_Page,
            wordFromVMRights(VMReadWrite),
            deviceMemory as usize,
            0,
        ),
        seL4_RISCV_Giga_Page => cap_frame_cap_new(
            asidInvalid,
            regionBase as usize,
            RISCV_Giga_Page,
            wordFromVMRights(VMReadWrite),
            deviceMemory as usize,
            0,
        ),
        seL4_RISCV_Mega_Page => cap_frame_cap_new(
            asidInvalid,
            regionBase as usize,
            RISCV_Mega_Page,
            wordFromVMRights(VMReadWrite),
            deviceMemory as usize,
            0,
        ),
        seL4_RISCV_PageTableObject => {
            cap_page_table_cap_new(asidInvalid, regionBase as usize, 0, 0)
        }
        _ => panic!("Invalid object type :{}", t),
    }
}

pub fn getObjectSize(t: usize, userObjSize: usize) -> usize {
    match t {
        seL4_TCBObject => seL4_TCBBits,
        seL4_EndpointObject => seL4_EndpointBits,
        seL4_NotificationObject => seL4_NotificationBits,
        seL4_CapTableObject => seL4_SlotBits + userObjSize,
        seL4_UntypedObject => userObjSize,
        seL4_RISCV_4K_Page | seL4_RISCV_PageTableObject => seL4_PageBits,
        seL4_RISCV_Mega_Page => seL4_LargePageBits,
        seL4_RISCV_Giga_Page => seL4_HugePageBits,
        _ => 0,
    }
}

#[no_mangle]
pub fn createNewObjects(
    t: usize,
    parent: *mut cte_t,
    destCNode: *mut cte_t,
    destOffset: usize,
    destLength: usize,
    regionBase: *mut usize,
    userSize: usize,
    deviceMemory: bool,
) {
    let objectSize = getObjectSize(t, userSize);
    let _totalObjectSize = destLength << objectSize;
    let nextFreeArea = regionBase;
    for i in 0..destLength {
        let cap = createObject(
            t,
            (nextFreeArea as usize + (i << objectSize)) as *mut usize,
            userSize,
            deviceMemory,
        );
        unsafe {
            insertNewCap(parent, destCNode.add(destOffset + i), &cap);
        }
    }
}

#[no_mangle]
pub fn decodeInvocation(
    invLabel: usize,
    length: usize,
    capIndex: usize,
    slot: *mut cte_t,
    cap: &mut cap_t,
    block: bool,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    // debug!("cap :{:#x} {:#x}")
    // debug!("type:{}", cap_get_capType(cap));
    match cap_get_capType(cap) {
        cap_null_cap => {
            debug!("Attempted to invoke a null cap {:#x}.", capIndex);
            unsafe {
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 0;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        cap_zombie_cap => {
            debug!("Attempted to invoke a zombie cap {:#x}.", capIndex);
            unsafe {
                current_syscall_error._type = seL4_InvalidCapability;
                current_syscall_error.invalidCapNumber = 0;
                return exception_t::EXCEPTION_SYSCALL_ERROR;
            }
        }
        cap_endpoint_cap => {
            if unlikely(cap_endpoint_cap_get_capCanSend(cap) == 0) {
                debug!("Attempted to invoke a read-only endpoint cap {}.", capIndex);
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            unsafe {
                setThreadState(ksCurThread, ThreadStateRestart);
            }
            return performInvocation_Endpoint(
                cap_endpoint_cap_get_capEPPtr(cap) as *mut endpoint_t,
                cap_endpoint_cap_get_capEPBadge(cap),
                cap_endpoint_cap_get_capCanGrant(cap) != 0,
                cap_endpoint_cap_get_capCanGrantReply(cap) != 0,
                block,
                call,
            );
        }
        cap_notification_cap => {
            if unlikely(cap_notification_cap_get_capNtfnCanSend(cap) == 0) {
                debug!(
                    "Attempted to invoke a read-only notification cap {}.",
                    capIndex
                );
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            unsafe {
                setThreadState(ksCurThread, ThreadStateRestart);
            }
            return performInvocation_Notification(
                cap_notification_cap_get_capNtfnPtr(cap) as *mut notification_t,
                cap_notification_cap_get_capNtfnBadge(cap),
            );
        }
        cap_reply_cap => {
            if unlikely(cap_reply_cap_get_capReplyMaster(cap) != 0) {
                debug!("Attempted to invoke an invalid reply cap {}.", capIndex);
                unsafe {
                    current_syscall_error._type = seL4_InvalidCapability;
                    current_syscall_error.invalidCapNumber = 0;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
            unsafe {
                setThreadState(ksCurThread, ThreadStateRestart);
            }
            return performInvocation_Reply(
                cap_reply_cap_get_capTCBPtr(cap) as *mut tcb_t,
                slot,
                cap_reply_cap_get_capReplyCanGrant(cap) != 0,
            );
        }
        cap_thread_cap => decodeTCBInvocation(invLabel, length, cap, slot, call, buffer),
        cap_domain_cap => decodeDomainInvocation(invLabel, length, buffer),
        cap_cnode_cap => decodeCNodeInvocation(invLabel, length, cap, buffer),
        cap_untyped_cap => decodeUntypedInvocation(invLabel, length, slot, cap, call, buffer),
        cap_irq_control_cap => decodeIRQControlInvocation(invLabel, length, slot, buffer),
        cap_irq_handler_cap => {
            decodeIRQHandlerInvocation(invLabel, cap_irq_handler_cap_get_capIRQ(cap))
        }
        _ => decodeRISCVMMUInvocation(invLabel, length, capIndex, slot, cap, call, buffer),
    }
}

#[no_mangle]
pub fn performInvocation_Reply(
    thread: *mut tcb_t,
    slot: *mut cte_t,
    canGrant: bool,
) -> exception_t {
    unsafe {
        doReplyTransfer(ksCurThread, thread, slot, canGrant);
    }
    exception_t::EXCEPTION_NONE
}

#[no_mangle]
pub fn Arch_isFrameType(_type: usize) -> bool {
    match _type {
        seL4_RISCV_4K_Page | seL4_RISCV_Giga_Page | seL4_RISCV_Mega_Page => true,
        _ => false,
    }
}
