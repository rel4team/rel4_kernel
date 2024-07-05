/*use crate::{common::{message_info::MessageLabel, structures::{exception_t, seL4_IPCBuffer},
    sel4_config::{seL4_IllegalOperation, seL4_TruncatedMessage, seL4_RangeError, tcbCTable, tcbVTable, seL4_InvalidCapability},
    utils::convert_to_mut_type_ref,
}, BIT};*/

use log::debug;
use sel4_common::arch::{frameRegNum, gpRegNum};
use sel4_common::message_info::MessageLabel;
use sel4_common::sel4_config::{
    seL4_IllegalOperation, seL4_InvalidCapability, seL4_RangeError, seL4_TruncatedMessage,
    tcbCTable, tcbVTable,
};
use sel4_common::structures::{exception_t, seL4_IPCBuffer};
use sel4_common::utils::convert_to_mut_type_ref;
use sel4_common::BIT;
use sel4_cspace::interface::{cap_t, cte_t, CapTag};
use sel4_ipc::notification_t;
use sel4_task::{get_currenct_thread, set_thread_state, tcb_t, ThreadState};

use crate::{
    kernel::boot::{current_syscall_error, get_extra_cap_by_index},
    syscall::{
        is_valid_vtable_root,
        utils::{check_ipc_buffer_vaild, check_prio, get_syscall_arg},
    },
};

use super::super::invoke_tcb::*;

#[cfg(feature = "ENABLE_SMP")]
use crate::ffi::remoteTCBStall;

pub const CopyRegisters_suspendSource: usize = 0;
pub const CopyRegisters_resumeTarget: usize = 1;
pub const CopyRegisters_transferFrame: usize = 2;
pub const CopyRegisters_transferInteger: usize = 3;
pub const ReadRegisters_suspend: usize = 0;

#[cfg(feature = "ENABLE_SMP")]
#[no_mangle]
pub fn decode_tcb_invocation(
    invLabel: MessageLabel,
    length: usize,
    cap: &cap_t,
    slot: &mut cte_t,
    call: bool,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    unsafe {
        remoteTCBStall(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()));
    }
    match invLabel {
        MessageLabel::TCBReadRegisters => decode_read_registers(cap, length, call, buffer),
        MessageLabel::TCBWriteRegisters => decode_write_registers(cap, length, buffer),
        MessageLabel::TCBCopyRegisters => decode_copy_registers(cap, length, buffer),
        MessageLabel::TCBSuspend => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invoke_tcb_suspend(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()))
        }
        MessageLabel::TCBResume => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invoke_tcb_resume(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()))
        }
        MessageLabel::TCBConfigure => decode_tcb_configure(cap, length, slot, buffer),
        MessageLabel::TCBSetPriority => decode_set_priority(cap, length, buffer),
        MessageLabel::TCBSetMCPriority => decode_set_mc_priority(cap, length, buffer),
        MessageLabel::TCBSetSchedParams => decode_set_sched_params(cap, length, buffer),
        MessageLabel::TCBSetIPCBuffer => decode_set_ipc_buffer(cap, length, slot, buffer),
        MessageLabel::TCBSetSpace => decode_set_space(cap, length, slot, buffer),
        MessageLabel::TCBBindNotification => decode_bind_notification(cap),
        MessageLabel::TCBUnbindNotification => decode_unbind_notification(cap),
        MessageLabel::TCBSetAffinity => decode_set_affinity(cap, length, buffer),
        MessageLabel::TCBSetTLSBase => decode_set_tls_base(cap, length, buffer),
        _ => unsafe {
            debug!("TCB: Illegal operation invLabel :{:?}", invLabel);
            current_syscall_error._type = seL4_IllegalOperation;
            exception_t::EXCEPTION_SYSCALL_ERROR
        },
    }
}

#[cfg(not(feature = "ENABLE_SMP"))]
#[no_mangle]
pub fn decode_tcb_invocation(
    invLabel: MessageLabel,
    length: usize,
    cap: &cap_t,
    slot: &mut cte_t,
    call: bool,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    match invLabel {
        MessageLabel::TCBReadRegisters => decode_read_registers(cap, length, call, buffer),
        MessageLabel::TCBWriteRegisters => decode_write_registers(cap, length, buffer),
        MessageLabel::TCBCopyRegisters => decode_copy_registers(cap, length, buffer),
        MessageLabel::TCBSuspend => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invoke_tcb_suspend(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()))
        }
        MessageLabel::TCBResume => {
            set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
            invoke_tcb_resume(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()))
        }
        MessageLabel::TCBConfigure => decode_tcb_configure(cap, length, slot, buffer),
        MessageLabel::TCBSetPriority => decode_set_priority(cap, length, buffer),
        MessageLabel::TCBSetMCPriority => decode_set_mc_priority(cap, length, buffer),
        MessageLabel::TCBSetSchedParams => decode_set_sched_params(cap, length, buffer),
        MessageLabel::TCBSetIPCBuffer => decode_set_ipc_buffer(cap, length, slot, buffer),
        MessageLabel::TCBSetSpace => decode_set_space(cap, length, slot, buffer),
        MessageLabel::TCBBindNotification => decode_bind_notification(cap),
        MessageLabel::TCBUnbindNotification => decode_unbind_notification(cap),
        MessageLabel::TCBSetTLSBase => decode_set_tls_base(cap, length, buffer),
        _ => unsafe {
            debug!("TCB: Illegal operation invLabel :{:?}", invLabel);
            current_syscall_error._type = seL4_IllegalOperation;
            exception_t::EXCEPTION_SYSCALL_ERROR
        },
    }
}

fn decode_read_registers(
    cap: &cap_t,
    length: usize,
    call: bool,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if length < 2 {
        debug!("TCB CopyRegisters: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let flags = get_syscall_arg(0, buffer);
    let n = get_syscall_arg(1, buffer);
    if n < 1 || n > frameRegNum + gpRegNum {
        debug!(
            "TCB ReadRegisters: Attempted to read an invalid number of registers:{}",
            n
        );
        unsafe {
            current_syscall_error._type = seL4_RangeError;
            current_syscall_error.rangeErrorMin = 1;
            current_syscall_error.rangeErrorMax = frameRegNum + gpRegNum;
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
    }
    let thread = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    if thread.is_current() {
        debug!("TCB ReadRegisters: Attempted to read our own registers.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_read_registers(thread, flags & BIT!(ReadRegisters_suspend), n, 0, call)
}

fn decode_write_registers(
    cap: &cap_t,
    length: usize,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
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
        debug!(
            "TCB WriteRegisters: Message too short for requested write size {}/{}",
            length - 2,
            w
        );
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let thread = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    if thread.is_current() {
        debug!("TCB WriteRegisters: Attempted to write our own registers.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_write_registers(thread, flags & BIT!(0), w, 0, buffer)
}

fn decode_copy_registers(
    cap: &cap_t,
    _length: usize,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    let flags = get_syscall_arg(0, buffer);

    let source_cap = get_extra_cap_by_index(0).unwrap().cap;

    if cap.get_cap_type() != CapTag::CapThreadCap {
        debug!("TCB CopyRegisters: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let src_tcb = convert_to_mut_type_ref::<tcb_t>(source_cap.get_tcb_ptr());
    return invoke_tcb_copy_registers(
        convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()),
        src_tcb,
        flags & BIT!(CopyRegisters_suspendSource),
        flags & BIT!(CopyRegisters_resumeTarget),
        flags & BIT!(CopyRegisters_transferFrame),
        flags & BIT!(CopyRegisters_transferInteger),
        0,
    );
}

fn decode_tcb_configure(
    target_thread_cap: &cap_t,
    msg_length: usize,
    target_thread_slot: &mut cte_t,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if msg_length < 4
        || get_extra_cap_by_index(0).is_none()
        || get_extra_cap_by_index(1).is_none()
        || get_extra_cap_by_index(2).is_none()
    {
        debug!("TCB CopyRegisters: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
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
        let mut buffer_slot_inner = if new_buffer_addr == 0 {
            None
        } else {
            get_extra_cap_by_index(2)
        };
        if let Some(buffer_slot) = buffer_slot_inner.as_deref_mut() {
            let dc_ret = buffer_slot.derive_cap(&cap);
            if dc_ret.status != exception_t::EXCEPTION_NONE {
                unsafe {
                    current_syscall_error._type = seL4_IllegalOperation;
                }
                return dc_ret.status;
            }
            cap = dc_ret.cap;
            let status = check_ipc_buffer_vaild(new_buffer_addr, &cap);
            if status != exception_t::EXCEPTION_NONE {
                return status;
            }
        }
        (buffer_slot_inner, cap)
    };
    let target_thread = convert_to_mut_type_ref::<tcb_t>(target_thread_cap.get_tcb_ptr());
    if target_thread.get_cspace(tcbCTable).is_long_running_delete()
        || target_thread.get_cspace(tcbVTable).is_long_running_delete()
    {
        debug!("TCB Configure: CSpace or VSpace currently being deleted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    match decode_set_space_args(croot_data, croot_cap, croot_slot) {
        Ok(cap) => croot_cap = cap,
        Err(status) => return status,
    }
    if croot_cap.get_cap_type() != CapTag::CapCNodeCap {
        debug!("TCB Configure: CSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    match decode_set_space_args(vroot_data, vroot_cap, vroot_slot) {
        Ok(cap) => vroot_cap = cap,
        Err(status) => return status,
    }
    if !is_valid_vtable_root(&vroot_cap) {
        debug!("TCB Configure: VSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    let status = invoke_tcb_set_space(
        target_thread,
        target_thread_slot,
        fault_ep,
        croot_cap,
        croot_slot,
        vroot_cap,
        vroot_slot,
    );
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }

    invoke_tcb_set_ipc_buffer(
        target_thread,
        target_thread_slot,
        new_buffer_addr,
        buffer_cap,
        buffer_slot,
    )
}

fn decode_set_priority(cap: &cap_t, length: usize, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    if length < 1 || get_extra_cap_by_index(0).is_none() {
        debug!("TCB SetPriority: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let new_prio = get_syscall_arg(0, buffer);
    let auth_cap = get_extra_cap_by_index(0).unwrap().cap;
    if auth_cap.get_cap_type() != CapTag::CapThreadCap {
        debug!("Set priority: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let auth_tcb = convert_to_mut_type_ref::<tcb_t>(auth_cap.get_tcb_ptr());
    let status = check_prio(new_prio, auth_tcb);
    if status != exception_t::EXCEPTION_NONE {
        return status;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_set_priority(
        convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()),
        new_prio,
    )
}

fn decode_set_mc_priority(
    cap: &cap_t,
    length: usize,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if length < 1 || get_extra_cap_by_index(0).is_none() {
        debug!("TCB SetMCPPriority: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let new_mcp = get_syscall_arg(0, buffer);
    let auth_cap = get_extra_cap_by_index(0).unwrap().cap;
    if auth_cap.get_cap_type() != CapTag::CapThreadCap {
        debug!("SetMCPriority: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let auth_tcb = convert_to_mut_type_ref::<tcb_t>(auth_cap.get_tcb_ptr());
    let status = check_prio(new_mcp, auth_tcb);
    if status != exception_t::EXCEPTION_NONE {
        debug!(
            "TCB SetMCPriority: Requested maximum controlled priority {} too high (max {}).",
            new_mcp, auth_tcb.tcbMCP
        );
        return status;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_set_mcp(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()), new_mcp)
}

fn decode_set_sched_params(
    cap: &cap_t,
    length: usize,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if length < 2 || get_extra_cap_by_index(0).is_some() {
        debug!("TCB SetSchedParams: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let new_mcp = get_syscall_arg(0, buffer);
    let new_prio = get_syscall_arg(1, buffer);
    let auth_cap = get_extra_cap_by_index(0).unwrap().cap;
    if auth_cap.get_cap_type() != CapTag::CapThreadCap {
        debug!("SetSchedParams: authority cap not a TCB.");
        unsafe {
            current_syscall_error._type = seL4_InvalidCapability;
            current_syscall_error.invalidCapNumber = 1;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let auth_tcb = convert_to_mut_type_ref::<tcb_t>(auth_cap.get_tcb_ptr());
    let status = check_prio(new_mcp, auth_tcb);
    if status != exception_t::EXCEPTION_NONE {
        debug!(
            "TCB SetSchedParams: Requested maximum controlled priority {} too high (max {}).",
            new_mcp, auth_tcb.tcbMCP
        );
        return status;
    }
    let status = check_prio(new_prio, auth_tcb);
    if status != exception_t::EXCEPTION_NONE {
        debug!(
            "TCB SetSchedParams: Requested priority {} too high (max {}).",
            new_prio, auth_tcb.tcbMCP
        );
        return status;
    }

    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    let target = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    invoke_tcb_set_mcp(target, new_mcp);
    invoke_tcb_set_priority(target, new_prio)
}

fn decode_set_ipc_buffer(
    cap: &cap_t,
    length: usize,
    slot: &mut cte_t,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if length < 1 || get_extra_cap_by_index(0).is_none() {
        debug!("TCB SetIPCBuffer: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let buffer_addr = get_syscall_arg(0, buffer);
    let (buffer_slot, buffer_cap) = if buffer_addr == 0 {
        (None, cap_t::new_null_cap())
    } else {
        let slot = get_extra_cap_by_index(0).unwrap();
        let cap = slot.cap;
        let dc_ret = slot.derive_cap(&cap);
        if dc_ret.status != exception_t::EXCEPTION_NONE {
            unsafe {
                current_syscall_error._type = seL4_IllegalOperation;
            }
            return dc_ret.status;
        }
        let status = check_ipc_buffer_vaild(buffer_addr, &dc_ret.cap);
        if status != exception_t::EXCEPTION_NONE {
            return status;
        }
        (Some(slot), dc_ret.cap)
    };

    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_set_ipc_buffer(
        convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()),
        slot,
        buffer_addr,
        buffer_cap,
        buffer_slot,
    )
}

fn decode_set_space(
    cap: &cap_t,
    length: usize,
    slot: &mut cte_t,
    buffer: Option<&seL4_IPCBuffer>,
) -> exception_t {
    if length < 3 || get_extra_cap_by_index(0).is_none() || get_extra_cap_by_index(1).is_none() {
        debug!("TCB SetSpace: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let fault_ep = get_syscall_arg(0, buffer);
    let croot_data = get_syscall_arg(1, buffer);
    let vroot_data = get_syscall_arg(2, buffer);
    let croot_slot = get_extra_cap_by_index(0).unwrap();
    let mut croot_cap = croot_slot.cap;
    let vroot_slot = get_extra_cap_by_index(1).unwrap();
    let mut vroot_cap = vroot_slot.cap;
    let target_thread = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    if target_thread.get_cspace(tcbCTable).is_long_running_delete()
        || target_thread.get_cspace(tcbVTable).is_long_running_delete()
    {
        debug!("TCB Configure: CSpace or VSpace currently being deleted.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    match decode_set_space_args(croot_data, croot_cap, croot_slot) {
        Ok(cap) => croot_cap = cap,
        Err(status) => return status,
    }
    if croot_cap.get_cap_type() != CapTag::CapCNodeCap {
        debug!("TCB Configure: CSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    match decode_set_space_args(vroot_data, vroot_cap, vroot_slot) {
        Ok(cap) => vroot_cap = cap,
        Err(status) => return status,
    }
    if !is_valid_vtable_root(&vroot_cap) {
        debug!("TCB Configure: VSpace cap is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_set_space(
        target_thread,
        slot,
        fault_ep,
        croot_cap,
        croot_slot,
        vroot_cap,
        vroot_slot,
    )
}

fn decode_bind_notification(cap: &cap_t) -> exception_t {
    if get_extra_cap_by_index(0).is_none() {
        debug!("TCB BindNotification: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let tcb = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    if tcb.tcbBoundNotification != 0 {
        debug!("TCB BindNotification: TCB already has a bound notification.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let ntfn_cap = get_extra_cap_by_index(0).unwrap().cap;
    if ntfn_cap.get_cap_type() != CapTag::CapNotificationCap {
        debug!("TCB BindNotification: Notification is invalid.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let ntfn = convert_to_mut_type_ref::<notification_t>(ntfn_cap.get_nf_ptr());

    if ntfn_cap.get_nf_can_receive() == 0 {
        debug!("TCB BindNotification: Insufficient access rights");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    if ntfn.get_queue_head() != 0 || ntfn.get_queue_tail() != 0 {
        debug!("TCB BindNotification: Notification cannot be bound.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_bind_notification(tcb, ntfn)
}

fn decode_unbind_notification(cap: &cap_t) -> exception_t {
    let tcb = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    if tcb.tcbBoundNotification == 0 {
        debug!("TCB BindNotification: TCB already has no bound Notification.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_unbind_notification(tcb)
}

#[cfg(feature = "ENABLE_SMP")]
fn decode_set_affinity(cap: &cap_t, length: usize, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    use sel4_common::sel4_config::CONFIG_MAX_NUM_NODES;

    if length < 1 {
        debug!("TCB SetAffinity: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }

    let affinity = get_syscall_arg(0, buffer);
    if affinity > CONFIG_MAX_NUM_NODES {
        debug!("TCB SetAffinity: Requested CPU does not exist.");
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    let tcb = convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr());
    invoke_tcb_set_affinity(tcb, affinity)
}

fn decode_set_tls_base(cap: &cap_t, length: usize, buffer: Option<&seL4_IPCBuffer>) -> exception_t {
    if length < 1 {
        debug!("TCB SetTLSBase: Truncated message.");
        unsafe {
            current_syscall_error._type = seL4_TruncatedMessage;
        }
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let base = get_syscall_arg(0, buffer);
    set_thread_state(get_currenct_thread(), ThreadState::ThreadStateRestart);
    invoke_tcb_set_tls_base(convert_to_mut_type_ref::<tcb_t>(cap.get_tcb_ptr()), base)
}

#[inline]
fn decode_set_space_args(
    root_data: usize,
    root_cap: cap_t,
    root_slot: &mut cte_t,
) -> Result<cap_t, exception_t> {
    let mut ret_root_cap = root_cap;
    if root_data != 0 {
        ret_root_cap = root_cap.update_data(false, root_data);
    }
    let dc_ret = root_slot.derive_cap(&ret_root_cap);
    if dc_ret.status != exception_t::EXCEPTION_NONE {
        unsafe {
            current_syscall_error._type = seL4_IllegalOperation;
        }
        return Err(dc_ret.status);
    }
    ret_root_cap = dc_ret.cap;
    return Ok(ret_root_cap);
}
