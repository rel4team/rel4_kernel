use common::{structures::{exception_t, seL4_IPCBuffer}, message_info::seL4_MessageInfo_t, sel4_config::{tcbCTable, tcbVTable, tcbBuffer}, utils::convert_to_option_mut_type_ref};
use cspace::interface::{cap_t, cte_t, same_object_as, cte_insert};
use ipc::cancel_ipc;
use task_manager::{tcb_t, badgeRegister, msgInfoRegister, get_currenct_thread, set_thread_state, ThreadState, FaultIP, NextIP, rescheduleRequired};

use crate::{config::{n_frameRegisters, n_msgRegisters, msgRegister, frameRegisters, n_gpRegisters, gpRegisters, thread_control_update_mcp, thread_control_update_space, thread_control_update_ipc_buffer, thread_control_update_priority}, syscall::utils::get_syscall_arg};

pub fn invoke_tcb_read_registers(src: &mut tcb_t, suspend_source: usize, n: usize, _arch: usize, call: bool) -> exception_t {
    let thread = get_currenct_thread();
    if suspend_source != 0 {
        cancel_ipc(src);
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
            thread.set_register(msgRegister[i + n_frameRegisters], src.get_register(gpRegisters[i]));
            i += 1;
        }

        if let Some(ipc_buffer) = op_ipc_buffer {
            while i < n_gpRegisters && i + n_frameRegisters < n {
                ipc_buffer.msg[i + n_frameRegisters] = src.get_register(gpRegisters[i]);
                i += 1;
            }
        }
        thread.set_register(msgInfoRegister, seL4_MessageInfo_t::new(0, 0, 0, i + j).to_word());
    }
    set_thread_state(thread, ThreadState::ThreadStateRunning);
    exception_t::EXCEPTION_NONE
}

pub fn invoke_tcb_write_registers(dest: &mut tcb_t, resumeTarget: usize, mut n: usize, _arch: usize, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
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
        dest.set_register(gpRegisters[i], get_syscall_arg(i + n_frameRegisters + 2, buffer));
        i += 1;
    }

    dest.set_register(NextIP, dest.get_register(FaultIP));

    if resumeTarget != 0 {
        cancel_ipc(dest);
        dest.restart();
    }
    if dest.is_current() {
        rescheduleRequired();
    }
    exception_t::EXCEPTION_NONE
}

pub fn invoke_tcb_copy_registers(dest: &mut tcb_t, src: &mut tcb_t, suspendSource: usize, resumeTarget: usize, transferFrame: usize, 
    _transferInteger: usize, _transferArch: usize) -> exception_t {
    if suspendSource != 0 {
        cancel_ipc(src);
        src.suspend();
    }
    if resumeTarget != 0 {
        cancel_ipc(dest);
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

pub fn invoke_tcb_suspend(thread: &mut tcb_t) -> exception_t {
    cancel_ipc(thread);
    thread.suspend();
    exception_t::EXCEPTION_NONE
}

pub fn invoke_tcb_resume(thread: &mut tcb_t) -> exception_t {
    cancel_ipc(thread);
    thread.restart();
    exception_t::EXCEPTION_NONE
}

pub fn invoke_tcb_thread_control(target: &mut tcb_t, slot: &mut cte_t, fault_ep: usize, mcp: usize, prio: usize, croot_new_cap: cap_t, croot_src_slot: &mut cte_t,
                                vroot_new_cap: cap_t, vroot_src_slot: &mut cte_t, buffer_addr: usize, buffer_cap: cap_t, buffer_src_slot: Option<&mut cte_t>,
                                update_flag: usize) -> exception_t {
    let target_cap = cap_t::new_thread_cap(target.get_ptr());
    if update_flag & thread_control_update_mcp != 0 {
        target.set_mcp_priority(mcp);
    }
    if update_flag & thread_control_update_space != 0 {
        target.tcbFaultHandler = fault_ep;
        let root_slot = target.get_cspace_mut_ref(tcbCTable);
        let status = root_slot.delete_all(true);
        if status != exception_t::EXCEPTION_NONE {
            return status;
        }
        if same_object_as(&croot_new_cap, &croot_src_slot.cap) && same_object_as(&target_cap, &slot.cap) {
            cte_insert(&croot_new_cap, croot_src_slot, root_slot);
        }
        
        let root_vslot = target.get_cspace_mut_ref(tcbVTable);
        let status = root_vslot.delete_all(true);
        if status != exception_t::EXCEPTION_NONE {
            return status;
        }
        if same_object_as(&vroot_new_cap, &vroot_src_slot.cap) && same_object_as(&target_cap, &slot.cap) {
            cte_insert(&vroot_new_cap, vroot_src_slot, root_vslot);
        }
    }

    if (update_flag & thread_control_update_ipc_buffer) != 0 {
        let buffer_slot = target.get_cspace_mut_ref(tcbBuffer);
        let status = buffer_slot.delete_all(true);
        if status != exception_t::EXCEPTION_NONE {
            return status;
        }
        target.tcbIPCBuffer = buffer_addr;
        if let Some(buffer_src_slot) =  buffer_src_slot {
            if same_object_as(&buffer_cap, &buffer_src_slot.cap) && same_object_as(&target_cap, &slot.cap) {
                cte_insert(&buffer_cap, buffer_src_slot, buffer_slot);
            }
        }
        if target.is_current() {
            rescheduleRequired();
        }
    }

    if (update_flag & thread_control_update_priority) != 0 {
        target.set_priority(prio);
    }
    exception_t::EXCEPTION_NONE
}


#[no_mangle]
pub fn invokeTCB_ThreadControl(
    target: *mut tcb_t,
    slot: *mut cte_t,
    faultep: usize,
    mcp: usize,
    prio: usize,
    cRoot_newCap: cap_t,
    cRoot_srcSlot: *mut cte_t,
    vRoot_newCap: cap_t,
    vRoot_srcSlot: *mut cte_t,
    bufferAddr: usize,
    bufferCap: cap_t,
    bufferSrcSlot: *mut cte_t,
    updateFlags: usize,
) -> exception_t {
    unsafe {
        invoke_tcb_thread_control(&mut *target, &mut *slot, faultep, mcp, prio, cRoot_newCap, &mut *cRoot_srcSlot,
            vRoot_newCap, &mut *vRoot_srcSlot, bufferAddr,
            bufferCap, convert_to_option_mut_type_ref::<cte_t>(bufferSrcSlot as usize), updateFlags)
    }
}