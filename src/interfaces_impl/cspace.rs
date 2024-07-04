use crate::config::CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION;
use crate::ffi::tcbDebugRemove;
use crate::interrupt::{deletingIRQHandler, isIRQPending, setIRQState, IRQState};
use crate::kernel::boot::current_lookup_fault;
use crate::syscall::safe_unbind_notification;
use sel4_common::sel4_config::{tcbCNodeEntries, tcbCTable, tcbVTable};
use sel4_common::structures::exception_t;
use sel4_common::utils::convert_to_mut_type_ref;
use sel4_cspace::compatibility::{ZombieType_ZombieTCB, Zombie_new};
use sel4_cspace::interface::{cap_t, finaliseCap_ret, CapTag};
use sel4_ipc::{endpoint_t, notification_t, Transfer};
use sel4_task::{get_currenct_thread, ksWorkUnitsCompleted, tcb_t};
use sel4_vspace::{
    asid_pool_t, asid_t, delete_asid, delete_asid_pool, find_vspace_for_asid, pte_t, unmapPage,
};

#[no_mangle]
pub fn Arch_finaliseCap(cap: &cap_t, final_: bool) -> finaliseCap_ret {
    let mut fc_ret = finaliseCap_ret::default();
    match cap.get_cap_type() {
        CapTag::CapFrameCap => {
            if cap.get_frame_mapped_asid() != 0 {
                match unmapPage(
                    cap.get_frame_size(),
                    cap.get_frame_mapped_asid(),
                    cap.get_frame_mapped_address(),
                    cap.get_frame_base_ptr(),
                ) {
                    Err(lookup_fault) => unsafe { current_lookup_fault = lookup_fault },
                    _ => {}
                }
            }
        }

        CapTag::CapPageTableCap => {
            if final_ && cap.get_pt_is_mapped() != 0 {
                let asid = cap.get_pt_mapped_asid();
                let find_ret = find_vspace_for_asid(asid);
                let pte = cap.get_pt_base_ptr();
                if find_ret.status == exception_t::EXCEPTION_NONE
                    && find_ret.vspace_root.unwrap() as usize == pte
                {
                    deleteASID(asid, pte as *mut pte_t);
                } else {
                    convert_to_mut_type_ref::<pte_t>(pte)
                        .unmap_page_table(asid, cap.get_pt_mapped_address());
                }
                if let Some(lookup_fault) = find_ret.lookup_fault {
                    unsafe {
                        current_lookup_fault = lookup_fault;
                    }
                }
            }
        }

        CapTag::CapASIDPoolCap => {
            if final_ {
                deleteASIDPool(cap.get_asid_base(), cap.get_asid_pool() as *mut asid_pool_t);
            }
        }
        _ => {}
    }
    fc_ret.remainder = cap_t::new_null_cap();
    fc_ret.cleanupInfo = cap_t::new_null_cap();
    fc_ret
}

#[no_mangle]
pub fn finaliseCap(cap: &cap_t, _final: bool, _exposed: bool) -> finaliseCap_ret {
    let mut fc_ret = finaliseCap_ret::default();

    if cap.isArchCap() {
        return Arch_finaliseCap(cap, _final);
    }
    match cap.get_cap_type() {
        CapTag::CapEndpointCap => {
            if _final {
                // cancelAllIPC(cap.get_ep_ptr() as *mut endpoint_t);
                convert_to_mut_type_ref::<endpoint_t>(cap.get_ep_ptr()).cancel_all_ipc()
            }
            fc_ret.remainder = cap_t::new_null_cap();
            fc_ret.cleanupInfo = cap_t::new_null_cap();
            return fc_ret;
        }
        CapTag::CapNotificationCap => {
            if _final {
                let ntfn = convert_to_mut_type_ref::<notification_t>(cap.get_nf_ptr());
                ntfn.safe_unbind_tcb();
                ntfn.cacncel_all_signal();
            }
            fc_ret.remainder = cap_t::new_null_cap();
            fc_ret.cleanupInfo = cap_t::new_null_cap();
            return fc_ret;
        }
        CapTag::CapReplyCap | CapTag::CapNullCap | CapTag::CapDomainCap => {
            fc_ret.remainder = cap_t::new_null_cap();
            fc_ret.cleanupInfo = cap_t::new_null_cap();
            return fc_ret;
        }
        _ => {
            if _exposed {
                panic!("finaliseCap: failed to finalise immediately.");
            }
        }
    }

    match cap.get_cap_type() {
        CapTag::CapCNodeCap => {
            return if _final {
                fc_ret.remainder = Zombie_new(
                    1usize << cap.get_cnode_radix(),
                    cap.get_cnode_radix(),
                    cap.get_cnode_ptr(),
                );
                fc_ret.cleanupInfo = cap_t::new_null_cap();
                fc_ret
            } else {
                fc_ret.remainder = cap_t::new_null_cap();
                fc_ret.cleanupInfo = cap_t::new_null_cap();
                fc_ret
            }
        }
        CapTag::CapThreadCap => {
            if _final {
                let tcb = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
                #[cfg(feature = "ENABLE_SMP")]
                unsafe {
                    crate::ffi::remoteTCBStall(tcb)
                };
                let cte_ptr = tcb.get_cspace_mut_ref(tcbCTable);
                safe_unbind_notification(tcb);
                tcb.cancel_ipc();
                tcb.suspend();
                unsafe {
                    tcbDebugRemove(tcb as *mut tcb_t);
                }
                fc_ret.remainder =
                    Zombie_new(tcbCNodeEntries, ZombieType_ZombieTCB, cte_ptr.get_ptr());
                fc_ret.cleanupInfo = cap_t::new_null_cap();
                return fc_ret;
            }
        }
        CapTag::CapZombieCap => {
            fc_ret.remainder = cap.clone();
            fc_ret.cleanupInfo = cap_t::new_null_cap();
            return fc_ret;
        }
        CapTag::CapIrqHandlerCap => {
            if _final {
                let irq = cap.get_irq_handler();
                deletingIRQHandler(irq);
                fc_ret.remainder = cap_t::new_null_cap();
                fc_ret.cleanupInfo = cap.clone();
                return fc_ret;
            }
        }
        _ => {
            fc_ret.remainder = cap_t::new_null_cap();
            fc_ret.cleanupInfo = cap_t::new_null_cap();
            return fc_ret;
        }
    }
    fc_ret.remainder = cap_t::new_null_cap();
    fc_ret.cleanupInfo = cap_t::new_null_cap();
    return fc_ret;
}

#[no_mangle]
pub fn post_cap_deletion(cap: &cap_t) {
    if cap.get_cap_type() == CapTag::CapIrqHandlerCap {
        let irq = cap.get_irq_handler();
        setIRQState(IRQState::IRQInactive, irq);
    }
}

#[no_mangle]
pub fn preemptionPoint() -> exception_t {
    unsafe {
        ksWorkUnitsCompleted += 1;
        if ksWorkUnitsCompleted >= CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION {
            ksWorkUnitsCompleted = 0;

            if isIRQPending() {
                return exception_t::EXCEPTION_PREEMTED;
            }
        }
        exception_t::EXCEPTION_NONE
    }
}

#[no_mangle]
fn deleteASID(asid: asid_t, vspace: *mut pte_t) {
    unsafe {
        if let Err(lookup_fault) = delete_asid(
            asid,
            vspace,
            &get_currenct_thread().get_cspace(tcbVTable).cap,
        ) {
            current_lookup_fault = lookup_fault;
        }
    }
}

#[no_mangle]
fn deleteASIDPool(asid_base: asid_t, pool: *mut asid_pool_t) {
    unsafe {
        if let Err(lookup_fault) = delete_asid_pool(
            asid_base,
            pool,
            &get_currenct_thread().get_cspace(tcbVTable).cap,
        ) {
            current_lookup_fault = lookup_fault;
        }
    }
}
