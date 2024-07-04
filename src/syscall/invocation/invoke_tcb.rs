use sel4_common::arch::*;
use sel4_common::{
    message_info::seL4_MessageInfo_t,
    sel4_config::{tcbBuffer, tcbCTable, tcbVTable},
    structures::{exception_t, seL4_IPCBuffer},
};
use sel4_cspace::interface::{cap_t, cte_insert, cte_t, same_object_as};
use sel4_ipc::{notification_t, Transfer};
use sel4_task::{get_currenct_thread, rescheduleRequired, set_thread_state, tcb_t, ThreadState};

use crate::{
    config::{frameRegisters, gpRegisters, n_frameRegisters, n_gpRegisters},
    syscall::{do_bind_notification, safe_unbind_notification, utils::get_syscall_arg},
};

pub fn invoke_tcb_read_registers(
    src: &mut tcb_t,
    suspend_source: usize,
    n: usize,
    _arch: usize,
    call: bool,
) -> exception_t {
    let thread = get_currenct_thread();
    if suspend_source != 0 {
        // cancel_ipc(src);
        src.cancel_ipc();
        src.suspend();
    }
    if call {
        let mut op_ipc_buffer = thread.lookup_mut_ipc_buffer(true);
        thread.set_register(badgeRegister, 0);
        let mut i: usize = 0;
        while i < n && i < n_frameRegisters && i < n_msgRegisters {
            // setRegister(thread, msgRegister[i], getRegister(src, frameRegisters[i]));
            thread.set_register(msgRegister[i], src.get_register(frameRegisters[i]));
            i += 1;
        }

        if let Some(ipc_buffer) = op_ipc_buffer.as_deref_mut() {
            while i < n && i < n_frameRegisters {
                ipc_buffer.msg[i] = src.get_register(frameRegisters[i]);
                i += 1;
            }
        }
        let j = i;
        i = 0;
        while i < n_gpRegisters && i + n_frameRegisters < n && i + n_frameRegisters < n_msgRegisters
        {
            thread.set_register(
                msgRegister[i + n_frameRegisters],
                src.get_register(gpRegisters[i]),
            );
            i += 1;
        }

        if let Some(ipc_buffer) = op_ipc_buffer {
            while i < n_gpRegisters && i + n_frameRegisters < n {
                ipc_buffer.msg[i + n_frameRegisters] = src.get_register(gpRegisters[i]);
                i += 1;
            }
        }
        thread.set_register(
            msgInfoRegister,
            seL4_MessageInfo_t::new(0, 0, 0, i + j).to_word(),
        );
    }
    set_thread_state(thread, ThreadState::ThreadStateRunning);
    exception_t::EXCEPTION_NONE
}

pub fn invoke_tcb_write_registers(
    dest: &mut tcb_t,
    resumeTarget: usize,
    mut n: usize,
    _arch: usize,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if n > n_frameRegisters + n_gpRegisters {
        n = n_frameRegisters + n_gpRegisters;
    }

    let mut i = 0;
    while i < n_frameRegisters && i < n {
        dest.set_register(frameRegisters[i], get_syscall_arg(i + 2, buffer));
        i += 1;
    }
    i = 0;
    while i < n_gpRegisters && i + n_frameRegisters < n {
        dest.set_register(
            gpRegisters[i],
            get_syscall_arg(i + n_frameRegisters + 2, buffer),
        );
        i += 1;
    }

    dest.set_register(NextIP, dest.get_register(FaultIP));

    if resumeTarget != 0 {
        // cancel_ipc(dest);
        dest.cancel_ipc();
        dest.restart();
    }
    if dest.is_current() {
        rescheduleRequired();
    }
    exception_t::EXCEPTION_NONE
}

pub fn invoke_tcb_copy_registers(
    dest: &mut tcb_t,
    src: &mut tcb_t,
    suspendSource: usize,
    resumeTarget: usize,
    transferFrame: usize,
    _transferInteger: usize,
    _transferArch: usize,
) -> exception_t {
    if suspendSource != 0 {
        // cancel_ipc(src);
        src.cancel_ipc();
        src.suspend();
    }
    if resumeTarget != 0 {
        // cancel_ipc(dest);
        dest.cancel_ipc();
        dest.restart();
    }
    if transferFrame != 0 {
        for i in 0..n_gpRegisters {
            dest.set_register(gpRegisters[i], src.get_register(gpRegisters[i]));
        }
    }
    if dest.is_current() {
        rescheduleRequired();
    }
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_tcb_suspend(thread: &mut tcb_t) -> exception_t {
    // cancel_ipc(thread);
    thread.cancel_ipc();
    thread.suspend();
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_tcb_resume(thread: &mut tcb_t) -> exception_t {
    // cancel_ipc(thread);
    thread.cancel_ipc();
    thread.restart();
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_tcb_set_mcp(target: &mut tcb_t, mcp: usize) -> exception_t {
    target.set_mcp_priority(mcp);
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_tcb_set_priority(target: &mut tcb_t, prio: usize) -> exception_t {
    target.set_priority(prio);
    exception_t::EXCEPTION_NONE
}

pub fn invoke_tcb_set_space(
    target: &mut tcb_t,
    slot: &mut cte_t,
    fault_ep: usize,
    croot_new_cap: cap_t,
    croot_src_slot: &mut cte_t,
    vroot_new_cap: cap_t,
    vroot_src_slot: &mut cte_t,
) -> exception_t {
    let target_cap = cap_t::new_thread_cap(target.get_ptr());
    target.tcbFaultHandler = fault_ep;
    let root_slot = target.get_cspace_mut_ref(tcbCTable);
    let status = root_slot.delete_all(true);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }
    if same_object_as(&croot_new_cap, &croot_src_slot.cap) && same_object_as(&target_cap, &slot.cap)
    {
        cte_insert(&croot_new_cap, croot_src_slot, root_slot);
    }

    let root_vslot = target.get_cspace_mut_ref(tcbVTable);
    let status = root_vslot.delete_all(true);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }
    if same_object_as(&vroot_new_cap, &vroot_src_slot.cap) && same_object_as(&target_cap, &slot.cap)
    {
        cte_insert(&vroot_new_cap, vroot_src_slot, root_vslot);
    }
    exception_t::EXCEPTION_NONE
}

pub fn invoke_tcb_set_ipc_buffer(
    target: &mut tcb_t,
    slot: &mut cte_t,
    buffer_addr: usize,
    buffer_cap: cap_t,
    buffer_src_slot: Option<&mut cte_t>,
) -> exception_t {
    let target_cap = cap_t::new_thread_cap(target.get_ptr());
    let buffer_slot = target.get_cspace_mut_ref(tcbBuffer);
    let status = buffer_slot.delete_all(true);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }
    target.tcbIPCBuffer = buffer_addr;
    if let Some(buffer_src_slot) = buffer_src_slot {
        if same_object_as(&buffer_cap, &buffer_src_slot.cap)
            && same_object_as(&target_cap, &slot.cap)
        {
            cte_insert(&buffer_cap, buffer_src_slot, buffer_slot);
        }
    }
    if target.is_current() {
        rescheduleRequired();
    }
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_tcb_bind_notification(tcb: &mut tcb_t, ntfn: &mut notification_t) -> exception_t {
    do_bind_notification(tcb, ntfn);
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_tcb_unbind_notification(tcb: &mut tcb_t) -> exception_t {
    safe_unbind_notification(tcb);
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_tcb_set_tls_base(thread: &mut tcb_t, base: usize) -> exception_t {
    thread.set_register(TLS_BASE, base);
    if thread.is_current() {
        rescheduleRequired();
    }
    exception_t::EXCEPTION_NONE
}

#[cfg(feature = "ENABLE_SMP")]
#[inline]
pub fn invoke_tcb_set_affinity(thread: &mut tcb_t, affinitiy: usize) -> exception_t {
    thread.sched_dequeue();
    unsafe {
        crate::ffi::migrateTCB(thread, affinitiy);
    }
    // debug!("tcb migrate: {}", thread.tcbAffinity);
    if thread.is_runnable() {
        thread.sched_append();
    }

    if thread.is_current() {
        rescheduleRequired();
    }
    exception_t::EXCEPTION_NONE
}
