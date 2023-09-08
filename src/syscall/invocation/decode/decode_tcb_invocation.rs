use common::{message_info::MessageLabel, structures::{exception_t, seL4_IPCBuffer}, 
    sel4_config::{seL4_IllegalOperation, seL4_TruncatedMessage, seL4_RangeError, tcbCTable, tcbVTable}, BIT, 
    utils::convert_to_mut_type_ref,
};
use cspace::interface::{cap_t, cte_t, CapTag, updateCapData};
use log::debug;
use task_manager::{tcb_t, set_thread_state, get_currenct_thread, ThreadState};

use crate::{object::tcb::{
    decodeSetPriority, decodeSetMCPriority, decodeSetSchedParams, decodeSetIPCBuffer, decodeSetSpace, 
    decodeBindNotification, decodeUnbindNotification, decodeSetTLSBase}, 
    kernel::{boot::{current_syscall_error, current_extra_caps, get_extra_cap_by_index}, vspace::{checkValidIPCBuffer, isValidVTableRoot}},
    syscall::{invocation::invoke_tcb::{invoke_tcb_write_registers, invoke_tcb_read_registers, invoke_tcb_copy_registers, invoke_tcb_suspend, invoke_tcb_resume, invoke_tcb_thread_control}, utils::get_syscall_arg},
    config::{n_frameRegisters, n_gpRegisters, thread_control_update_space, thread_control_update_ipc_buffer}};


    
pub const CopyRegisters_suspendSource: usize = 0;
pub const CopyRegisters_resumeTarget: usize = 1;
pub const CopyRegisters_transferFrame: usize = 2;
pub const CopyRegisters_transferInteger: usize = 3;
pub const ReadRegisters_suspend: usize = 0;

#[no_mangle]
pub fn decodeTCBInvocation(
    invLabel: MessageLabel,
    length: usize,
    cap: &cap_t,
    slot: *mut cte_t,
    call: bool,
    buffer: *mut usize,
) -> exception_t {
    match invLabel {
        MessageLabel::TCBReadRegisters => decode_read_registers(cap, length, call, Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(buffer as usize))),
        MessageLabel::TCBWriteRegisters => decode_write_registers(cap, length, Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(buffer as usize))),
        MessageLabel::TCBCopyRegisters => decode_copy_registers(cap, length, Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(buffer as usize))),
        MessageLabel::TCBSuspend => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invoke_tcb_suspend(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()))
        }
        MessageLabel::TCBResume => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invoke_tcb_resume(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()))
        }
        MessageLabel::TCBConfigure => decode_tcb_configure(cap, length, unsafe { &mut *slot }, 
            Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(buffer as usize))),
        MessageLabel::TCBSetPriority => decodeSetPriority(cap, length, buffer),
        MessageLabel::TCBSetMCPriority => decodeSetMCPriority(cap, length, buffer),
        MessageLabel::TCBSetSchedParams => decodeSetSchedParams(cap, length, buffer),
        MessageLabel::TCBSetIPCBuffer => decodeSetIPCBuffer(cap, length, slot as *mut cte_t, buffer),
        MessageLabel::TCBSetSpace => decodeSetSpace(cap, length, slot as *mut cte_t, buffer),
        MessageLabel::TCBBindNotification => decodeBindNotification(cap),
        MessageLabel::TCBUnbindNotification => decodeUnbindNotification(cap),
        MessageLabel::TCBSetTLSBase => decodeSetTLSBase(cap, length, buffer),
        _ => unsafe {
            debug!("TCB: Illegal operation invLabel :{:?}", invLabel);
            current_syscall_error._type = seL4_IllegalOperation;
            exception_t::EXCEPTION_SYSCALL_ERROR
        },
    }
}


fn decode_read_registers(cap: &cap_t, length: usize, call: bool, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    if length < 2 {
        debug!("TCB CopyRegisters: Truncated message.");
        unsafe { current_syscall_error._type = seL4_TruncatedMessage; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let flags = get_syscall_arg(0, buffer);
    let n = get_syscall_arg(1, buffer);
    if n < 1 || n > n_frameRegisters + n_gpRegisters {
        debug!("TCB ReadRegisters: Attempted to read an invalid number of registers:{}", n);
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = n_frameRegisters + n_gpRegisters;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let thread = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    if thread .is_current() {
        debug!("TCB ReadRegisters: Attempted to read our own registers.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_read_registers(thread, flags & BIT!(ReadRegisters_suspend), n, 0, call)
}

fn decode_write_registers(cap: &cap_t, length: usize, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    if length < 2 {
        unsafe {
            debug!("TCB CopyRegisters: Truncated message.");
            current_syscall_error._type = seL4_TruncatedMessage;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let flags = get_syscall_arg(0, buffer);
    let w = get_syscall_arg(1, buffer);

    if length - 2 < w {
        debug!("TCB WriteRegisters: Message too short for requested write size {}/{}", length - 2, w);
        unsafe { current_syscall_error._type = seL4_TruncatedMessage; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let thread = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    if thread.is_current() {
        debug!("TCB WriteRegisters: Attempted to write our own registers.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_write_registers(thread, flags & BIT!(0), w, 0, buffer)
}

fn decode_copy_registers(cap: &cap_t, _length: usize, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    let flags = get_syscall_arg(0, buffer);

    let source_cap = unsafe {
        &(*current_extra_caps.excaprefs[0]).cap
    };

    if cap.get_cap_type() != CapTag::CapThreadCap {
        debug!("TCB CopyRegisters: Truncated message.");
        unsafe { current_syscall_error._type = seL4_TruncatedMessage; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let src_tcb = convert_to_mut_type_ref::<tcb_t>(source_cap.get_tcb_ptr());
    return invoke_tcb_copy_registers(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()), src_tcb, 
                        flags & BIT!(CopyRegisters_suspendSource), flags & BIT!(CopyRegisters_resumeTarget),
                        flags & BIT!(CopyRegisters_transferFrame), flags & BIT!(CopyRegisters_transferInteger), 0)
}

fn decode_tcb_configure(target_thread_cap: &cap_t, msg_length: usize, target_thread_slot: &mut cte_t, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    if msg_length < 4 || get_extra_cap_by_index(0).is_none() || get_extra_cap_by_index(1).is_none() || get_extra_cap_by_index(2).is_none() {
        debug!("TCB CopyRegisters: Truncated message.");
        unsafe { current_syscall_error._type = seL4_TruncatedMessage; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let fault_ep = get_syscall_arg(0, buffer);
    let croot_data = get_syscall_arg(1, buffer);
    let vroot_data = get_syscall_arg(2, buffer);
    let new_buffer_addr = get_syscall_arg(3, buffer);
    let croot_slot = get_extra_cap_by_index(0).unwrap();
    let mut croot_cap = croot_slot.cap;
    let vroot_slot = get_extra_cap_by_index(1).unwrap();
    let mut vroot_cap = vroot_slot.cap;

    let (buffer_slot, buffer_cap) = {
        let mut cap = get_extra_cap_by_index(2).unwrap().cap;
        let mut buffer_slot_inner = if new_buffer_addr == 0 { None } else { get_extra_cap_by_index(2) };
        if let Some(buffer_slot) = buffer_slot_inner.as_deref_mut() {
            let dc_ret = buffer_slot.derive_cap(&cap);
            if dc_ret.status != exception_t::EXCEPTION_NONE {
                unsafe { current_syscall_error._type = seL4_IllegalOperation; }
                return dc_ret.status;
            }
            cap = dc_ret.cap;
            let status = checkValidIPCBuffer(new_buffer_addr, &cap);
            if status != exception_t::EXCEPTION_NONE {
                return status;
            }
        }
        (buffer_slot_inner, cap)
    };
    let target_thread = convert_to_mut_type_ref::<tcb_t>(target_thread_cap.get_tcb_ptr());
    if target_thread.get_cspace(tcbCTable).is_long_running_delete()
        || target_thread.get_cspace(tcbVTable).is_long_running_delete() {
        debug!("TCB Configure: CSpace or VSpace currently being deleted.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    match decode_set_space_args(croot_data, croot_cap, croot_slot) {
        Ok(cap) => croot_cap = cap,
        Err(status) => return status,
    }
    if croot_cap.get_cap_type() != CapTag::CapCNodeCap {
        debug!("TCB Configure: CSpace cap is invalid.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    match decode_set_space_args(vroot_data, vroot_cap, vroot_slot) {
        Ok(cap) => vroot_cap = cap,
        Err(status) => return status,
    }
    if !isValidVTableRoot(&vroot_cap) {
        debug!("TCB Configure: VSpace cap is invalid.");
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_thread_control(target_thread, target_thread_slot, fault_ep, 0, 0,
        croot_cap, croot_slot, vroot_cap, vroot_slot,
        new_buffer_addr, buffer_cap, buffer_slot, thread_control_update_space | thread_control_update_ipc_buffer)
}

#[inline]
fn decode_set_space_args(root_data: usize, root_cap: cap_t, root_slot: &mut cte_t) -> Result<cap_t, exception_t> {
    let mut ret_root_cap = root_cap;
    if root_data != 0 {
        ret_root_cap = updateCapData(false, root_data, &root_cap);
    }
    let dc_ret = root_slot.derive_cap(&ret_root_cap);
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        unsafe { current_syscall_error._type = seL4_IllegalOperation; }
        return Err(dc_ret.status);
    }
    ret_root_cap = dc_ret.cap;
    return Ok(ret_root_cap);
}