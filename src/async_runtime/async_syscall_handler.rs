use crate::BIT;
use crate::MASK;
use log::debug;
use crate::async_runtime::new_buffer::{NewBuffer, IPCItem};
use crate::async_runtime::utils::yield_now;
use crate::common::{utils::{convert_to_mut_type_ref, pageBitsForSize}, message_info::{AsyncMessageLabel, AsyncErrorLabel}, object::ObjectType, sbi::console_putchar, structures::exception_t, sel4_config::*};
use crate::cspace::interface::{cap_t, cte_t, CapTag, seL4_CapRights_t};
use crate::task_manager::{tcb_t, get_currenct_thread, ipc::notification_t};
use crate::uintr;
use crate::uintr::uipi_send;
use crate::vspace::{checkVPAlignment, kpptr_to_paddr, pptr_to_paddr, find_vspace_for_asid, vm_attributes_t, pte_t};
// use crate::uintc::{KERNEL_SENDER_POOL_IDX, NET_UINTR_IDX, UIntrReceiver, UIntrSTEntry};
use core::sync::atomic::Ordering::SeqCst;
use core::intrinsics::unlikely;
use crate::common::sbi::get_time;
use crate::kernel::boot::current_syscall_error;
use crate::syscall::{alignUp, FREE_INDEX_TO_OFFSET, GET_FREE_REF, invocation::{invoke_cnode::*, invoke_untyped::invoke_untyped_retype, invoke_mmu_op::*}, invocation::decode::decode_untyped_invocation::{check_object_type, check_cnode_slot}};
use crate::syscall::utils::lookup_slot_for_cnode_op;
use crate::config::USER_TOP;
use crate::utils::busy_wait;
use crate::async_runtime::{register_receiver,send_signal};
// 每个线程对应一个内核syscall handler协程
// 每个线程在用户态只能发现自己的内核协程不在线
// 当线程陷入内核去激活协程时，所有的内核协程都不在线（因为内核独占）
// 线程陷入内核只是去激活协程，并不会执行协程，而是发送ipi去挑选空闲cpu来执行所有被激活的协程
    // 当没有cpu空闲时，还是等待时钟中断？
    // 当系统调用频率不够高时，仍然需要额外陷入内核，但等时钟中断的话就不会有额外的特权级切换开销
// 当前在每个核心的时钟中断时检查每个buffer的req标志位，被设置标志位的buffer对应的协程被内核主动激活并执行。
// todo：新增激活内核协程的系统调用，不需要获取内核锁，涉及到的数据安全靠自旋锁保证



pub async fn async_syscall_handler(ntfn_cap: cap_t, new_buffer_cap: cap_t, tcb: &mut tcb_t, sender_id: usize) {
    // debug!("async_syscall_handler: enter");
    // 异常处理
    let error_id: isize = -1;
    if sender_id == (error_id as usize) {
        debug!("async_syscall_handler: fail to register sender!");
        return;
    }
    let new_buffer = convert_to_mut_type_ref::<NewBuffer>(new_buffer_cap.get_frame_base_ptr());
    debug!("async_syscall_handler: new_buffer_cap: {}, new_buffer_ptr: {:#x}", new_buffer_cap.get_cap_ptr(), new_buffer_cap.get_frame_base_ptr());
    // let badge = ntfn_cap.get_nf_badge();
    let mut need_switch = false;
    loop {
        //如果buffer里有东西
        if let Some(mut item) = new_buffer.req_items.get_first_item() {
            need_switch = false;
            let label: AsyncMessageLabel = AsyncMessageLabel::from(item.msg_info);
            debug!("async_syscall_handler: handle async syscall: {:?}", label);
            match label {
                AsyncMessageLabel::UntypedRetype => {
                    handle_async_untyped_retype(&mut item, tcb);
                }
                AsyncMessageLabel::RISCVPageGetAddress => {
                    handle_async_page_get_address(&mut item, tcb);
                }
                AsyncMessageLabel::PutChar => {
                    handle_async_putchar(&mut item, tcb);
                }
                AsyncMessageLabel::PutString => {
                    handle_async_putstring(&mut item, tcb);
                }
                AsyncMessageLabel::TCBBindNotification => {
                    handle_async_tcb_bind_notification(&mut item, tcb);
                }
                AsyncMessageLabel::TCBUnbindNotification => {
                    handle_async_tcb_unbind_notification(&mut item, tcb);
                }
                AsyncMessageLabel::CNodeRevoke | AsyncMessageLabel::CNodeRotate | AsyncMessageLabel::CNodeCancelBadgedSends | AsyncMessageLabel::CNodeDelete | AsyncMessageLabel::CNodeCopy | AsyncMessageLabel::CNodeMint => {
                    handle_async_cnode_syscall(&mut item, tcb, label);
                }
                AsyncMessageLabel::RISCVPageTableMap => {
                    handle_async_page_table_map(&mut item, tcb);
                }
                AsyncMessageLabel::RISCVPageTableUnmap => {
                    handle_async_page_table_unmap(&mut item, tcb);
                }
                AsyncMessageLabel::RISCVPageMap => {
                    handle_async_page_map(&mut item, tcb);
                }
                AsyncMessageLabel::RISCVPageUnmap => {
                    handle_async_page_unmap(&mut item, tcb);
                }
                _ => {
                    handle_async_unknown_label(&mut item, tcb);
                }
            };
            new_buffer.res_items.write_free_item(&item).unwrap();
            if new_buffer.recv_reply_status.load(SeqCst) == false {
                new_buffer.recv_reply_status.store(true, SeqCst);
                send_signal(1);
                // todo: send uintr
                // debug!("async_syscall_handler: send uintr sender_id: {}", sender_id);
                // unsafe {
                //     send_async_syscall_uintr(sender_id);
                // }
            }
        } else {//如果没有
            // if !need_switch {
            //     need_switch = true;
            //     busy_wait(2000);
            //     continue;
            // }
            debug!("[async_syscall_handler] all items in buffer reply");
            new_buffer.recv_req_status.store(false, SeqCst);
            register_receiver(1, 1);
            yield_now().await;
            debug!("wake recv co");
        }
    }
}

unsafe fn send_async_syscall_uintr(offset: usize) {
    // let uist_idx = *KERNEL_SENDER_POOL_IDX.lock();
    // let frame_addr = crate::uintc::UINTR_ST_POOL.as_ptr().offset((uist_idx * core::mem::size_of::<UIntrSTEntry>() * crate::uintc::config::UINTC_ENTRY_NUM) as isize) as usize;
    // uintr::suist::write((1 << 63) | (1 << 44) | (kpptr_to_paddr(frame_addr) >> 0xC));
    // uipi_send(offset);
}

fn handle_async_unknown_label(item: &mut IPCItem, tcb: &mut tcb_t) {
    debug!("async_syscall_handler: TODO: handle unknown label");
    item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
}

fn handle_async_untyped_retype(item: &mut IPCItem, tcb: &mut tcb_t) {
    let service_cptr = item.extend_msg[0] as usize;
    // 根据service的CPtr获取slot
    let service_lu_ret = tcb.lookup_slot(service_cptr);
    if unlikely(service_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_untyped_retype: Invocation of invalid service cap {:#x}.", service_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let service_slot: &mut cte_t = unsafe {&mut *service_lu_ret.slot };
    let service_cap = &service_slot.cap;
    // 其他参数
    let new_type_usize = item.extend_msg[1] as usize;
    let user_obj_size = item.extend_msg[2] as usize;
    let root_cptr = item.extend_msg[3] as usize;
    let node_index = item.extend_msg[4] as usize;
    let node_depth = item.extend_msg[5] as usize;
    let node_offset = item.extend_msg[6] as usize;
    let node_window = item.extend_msg[7] as usize;
    let op_new_type = ObjectType::from_usize(new_type_usize);
    if op_new_type.is_none() {
        debug!("handler_untyped_retype: Untyped Retype: Invalid object type. {}", new_type_usize);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let new_type = op_new_type.unwrap();
    let obj_size = new_type.get_object_size(user_obj_size);
    // TODO: Translate
    if user_obj_size >= wordBits || obj_size > seL4_MaxUntypedBits {
        debug!("handle_async_untyped_retype: Untyped Retype: Invalid object size. {} : {}", user_obj_size, obj_size);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let status = check_object_type(new_type, user_obj_size);
    if status != exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let mut node_cap = cap_t::default();
    let status = get_target_cnode(root_cptr, tcb, node_index, node_depth, &mut node_cap);
    if status != exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }

    let status = check_cnode_slot(&node_cap, node_offset, node_window);
    if status != exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let status = service_slot.ensure_no_children();
    let (free_index, reset) =  if status != exception_t::EXCEPTION_NONE {
        // 原始 untype 有子节点
        (service_cap.get_untyped_free_index(), false)
    } else {
        (0, true)
    };

    let free_ref = GET_FREE_REF(service_cap.get_untyped_ptr(), free_index);
    let untyped_free_bytes = BIT!(service_cap.get_untyped_block_size()) - FREE_INDEX_TO_OFFSET(free_index);

    if (untyped_free_bytes >> obj_size) < node_window {
        debug!("handle_async_untyped_retype: Untyped Retype: Insufficient memory({} * {} bytes needed, {} bytes available)", node_window,
                if obj_size >=  wordBits { -1 } else { 1i64 << obj_size }, untyped_free_bytes);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }

    let device_mem = service_cap.get_untyped_is_device() != 0;
    if device_mem && !new_type.is_arch_type() && new_type != ObjectType::UnytpedObject {
        debug!("handle_async_untyped_retype: Untyped Retype: Creating kernel objects with device untyped");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let aligned_free_ref = alignUp(free_ref, obj_size);

    // debug!("handle_async_untyped_retype: invoke_untyped_retype");
    
    let status = invoke_untyped_retype(service_slot, reset, aligned_free_ref, new_type, user_obj_size,
        convert_to_mut_type_ref::<cte_t>(node_cap.get_cnode_ptr()),
        node_offset, node_window, device_mem as usize);
    if status == exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    } else {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
    }
}

fn get_target_cnode(root_cptr: usize, tcb: &mut tcb_t, node_index: usize, node_depth: usize, node_cap: &mut cap_t) -> exception_t {
    // 解码cptr
    // 根据service的CPtr获取slot
    let root_lu_ret = tcb.lookup_slot(root_cptr);
    if unlikely(root_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("get_target_cnode: Invocation of invalid root cap {:#x}.", root_cptr);
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let root_slot: &mut cte_t = unsafe {&mut *root_lu_ret.slot };
    // 和原函数一致
    let target_node_cap = if node_depth == 0 {
        root_slot.cap
    } else {
        let root_cap = root_slot.cap;
        let lu_ret = lookup_slot_for_cnode_op(false, &root_cap, node_index, node_depth);
        if lu_ret.status != exception_t::EXCEPTION_NONE {
            debug!("get_target_cnode: Untyped Retype: Invalid destination address.");
            return lu_ret.status;
        }
        unsafe { (*lu_ret.slot).cap }
    };

    if target_node_cap.get_cap_type() != CapTag::CapCNodeCap {
        debug!("get_target_cnode: Untyped Retype: Destination cap invalid or read-only.");
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    *node_cap = target_node_cap;
    exception_t::EXCEPTION_NONE
}

fn handle_async_page_get_address(item: &mut IPCItem, tcb: &mut tcb_t) {
    let cptr = item.extend_msg[0] as usize;
    let lu_ret = tcb.lookup_slot(cptr);
    if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_get_address: Invocation of invalid cap {:#x}.", cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let slot: &mut cte_t = unsafe {&mut *lu_ret.slot };
    let vbase_ptr = slot.cap.get_frame_base_ptr();
    let paddr = pptr_to_paddr(vbase_ptr);
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    item.extend_msg[1] = (paddr >> 48) as u16;
    item.extend_msg[2] = (paddr >> 32) as u16;
    item.extend_msg[3] = (paddr >> 16) as u16;
    item.extend_msg[4] = paddr as u16;     
}

fn handle_async_putchar(item: &mut IPCItem, tcb: &mut tcb_t) {
    console_putchar(item.extend_msg[0] as usize);
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
}

fn handle_async_putstring(item: &mut IPCItem, tcb: &mut tcb_t) {
    let size = item.extend_msg[0] as usize;
    for i in 0..size {
        console_putchar(item.extend_msg[1 + i] as usize);
    }
    // console_putchar('\n' as usize);
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
}

fn handle_async_tcb_bind_notification(item: &mut IPCItem, tcb: &mut tcb_t) {
    let target_tcb_cptr = item.extend_msg[0] as usize;
    let ntfn_cptr = item.extend_msg[1] as usize;
    // 根据TCB的CPtr获取slot
    let target_tcb_lu_ret = tcb.lookup_slot(target_tcb_cptr);
    if unlikely(target_tcb_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_bind_notification: Invocation of invalid tcb cap {:#x}.", target_tcb_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let target_tcb_slot: &mut cte_t = unsafe {&mut *target_tcb_lu_ret.slot };
    // 通过TCB的slot获取capability，进而获取指针得到引用
    let target_tcb = convert_to_mut_type_ref::<tcb_t>(target_tcb_slot.cap.get_tcb_ptr());
    if target_tcb.tcbBoundNotification != 0 {
        debug!("TCB BindNotification: TCB already has a bound notification.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    // 根据Notification的CPtr获取slot
    let ntfn_lu_ret = tcb.lookup_slot(ntfn_cptr);
    if unlikely(ntfn_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_bind_notification: Invocation of invalid Ntfn cap {:#x}.", ntfn_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let ntfn_slot: &mut cte_t = unsafe {&mut *ntfn_lu_ret.slot };
    // 通过Notification的slot获取capability，进而获取指针得到引用
    let ntfn_cap = ntfn_slot.cap;
    if ntfn_cap.get_cap_type() != CapTag::CapNotificationCap {
        debug!("handle_async_bind_notification: TCB BindNotification: Notification is invalid.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    // 通过Notification的Capability获取Notification指针得到引用
    let ntfn = convert_to_mut_type_ref::<notification_t>(ntfn_cap.get_nf_ptr());
    if ntfn_cap.get_nf_can_receive() == 0 {
        debug!("handle_async_bind_notification: TCB BindNotification: Insufficient access rights");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    if ntfn.get_queue_head() != 0 || ntfn.get_queue_tail() != 0 {
        debug!("handle_async_bind_notification: TCB BindNotification: Notification cannot be bound.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    debug!("handle_async_unbind_notification: Before Bind");
    debug!("handle_async_bind_notification: TCB: tcbBindNotification: {:#x}", target_tcb.tcbBoundNotification);
    debug!("handle_async_bind_notification: TCB: get_ptr: {:#x}", target_tcb.get_ptr());
    debug!("handle_async_bind_notification: Notification: bound_tcb: {:#x}", ntfn.get_bound_tcb());
    debug!("handle_async_bind_notification: Notification: get_ptr: {:#x}", ntfn.get_ptr());    
    ntfn.bind_tcb(target_tcb);
    target_tcb.bind_notification(ntfn.get_ptr());
    debug!("handle_async_unbind_notification: After Bind");
    debug!("handle_async_bind_notification: TCB: tcbBindNotification: {:#x}", target_tcb.tcbBoundNotification);
    debug!("handle_async_bind_notification: TCB: get_ptr: {:#x}", target_tcb.get_ptr());
    debug!("handle_async_bind_notification: Notification: bound_tcb: {:#x}", ntfn.get_bound_tcb());
    debug!("handle_async_bind_notification: Notification: get_ptr: {:#x}", ntfn.get_ptr());
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
}

fn handle_async_tcb_unbind_notification(item: &mut IPCItem, tcb: &mut tcb_t) {
    // 根据CPtr获取slot
    let target_tcb_cptr = item.extend_msg[0] as usize;
    let lu_ret = tcb.lookup_slot(target_tcb_cptr);
    if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_unbind_notification: Invocation of invalid cap {:#x}.", target_tcb_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let slot: &mut cte_t = unsafe {&mut *lu_ret.slot };
    // 获取Capability，进而获取指针得到引用
    let target_tcb = convert_to_mut_type_ref::<tcb_t>(slot.cap.get_tcb_ptr());
    // 解除绑定
    if target_tcb.tcbBoundNotification == 0 {
        debug!("handle_async_unbind_notification: TCB BindNotification: TCB already has no bound Notification.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let ntfn_addr = target_tcb.tcbBoundNotification;
    let ntfn = convert_to_mut_type_ref::<notification_t>(ntfn_addr);
    debug!("handle_async_unbind_notification: Before Unbind");
    debug!("handle_async_unbind_notification: TCB: tcbBindNotification: {:#x}", target_tcb.tcbBoundNotification);
    debug!("handle_async_unbind_notification: TCB: get_ptr: {:#x}", target_tcb.get_ptr());
    debug!("handle_async_unbind_notification: Notification: bound_tcb: {:#x}", ntfn.get_bound_tcb());
    debug!("handle_async_unbind_notification: Notification: get_ptr: {:#x}", ntfn.get_ptr());
    ntfn.unbind_tcb();
    target_tcb.unbind_notification();
    debug!("handle_async_unbind_notification: After Unbind");
    debug!("handle_async_unbind_notification: TCB: tcbBindNotification: {:#x}", target_tcb.tcbBoundNotification);
    debug!("handle_async_unbind_notification: TCB: get_ptr: {:#x}", target_tcb.get_ptr());
    debug!("handle_async_unbind_notification: Notification: bound_tcb: {:#x}", ntfn.get_bound_tcb());
    debug!("handle_async_unbind_notification: Notification: get_ptr: {:#x}", ntfn.get_ptr());
    item.extend_msg[0] = AsyncErrorLabel::NoError.into();
}

fn handle_async_cnode_syscall(item: &mut IPCItem, tcb: &mut tcb_t, label: AsyncMessageLabel) {
    let label = AsyncMessageLabel::from(item.msg_info);
    // 根据dest_root_cptr获取dest_root_cap
    let dest_root_cptr = item.extend_msg[0] as usize;
    let dest_index = item.extend_msg[1] as usize;
    let dest_depth = item.extend_msg[2] as usize;
    let dest_root_lu_ret = tcb.lookup_slot(dest_root_cptr);
    if unlikely(dest_root_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_cnode_syscall: Invocation of invalid cap {:#x}.", dest_root_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let dest_root_slot = unsafe {&mut *dest_root_lu_ret.slot };
    let dest_root_cap = dest_root_slot.cap;
    // 获取dest_slot
    let dest_slot_lu_ret = lookup_slot_for_cnode_op(false, &dest_root_cap, dest_index, dest_depth);
    if dest_slot_lu_ret.status != exception_t::EXCEPTION_NONE {
        debug!("handle_async_cnode_copy: CNode operation: Dest Target slot invalid.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let dest_slot = convert_to_mut_type_ref::<cte_t>(dest_slot_lu_ret.slot as usize);
    let error = match label {
        AsyncMessageLabel::CNodeCopy | AsyncMessageLabel::CNodeMint => handle_async_cnode_syscall_with_two_slot(item, tcb, dest_slot, label),
        AsyncMessageLabel::CNodeDelete => handle_async_cnode_delete(dest_slot),
        AsyncMessageLabel::CNodeCancelBadgedSends => invoke_cnode_cancel_badged_sends(dest_slot),
        AsyncMessageLabel::CNodeRevoke => invoke_cnode_revoke(dest_slot),
        _ => exception_t::EXCEPTION_SYSCALL_ERROR
    };
    if error == exception_t::EXCEPTION_NONE {
        item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    } else {
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
    }
}

fn handle_async_cnode_syscall_with_two_slot(item: &mut IPCItem, tcb: &mut tcb_t, dest_slot: &mut cte_t, label: AsyncMessageLabel) -> exception_t{
    if dest_slot.cap.get_cap_type() != CapTag::CapNullCap {
        debug!("handle_async_cnode_syscall_with_two_slot: CNode Copy: Destination not empty.");
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    // src有关参数
    let src_root_cptr = item.extend_msg[3] as usize;
    let src_index = item.extend_msg[4] as usize;
    let src_depth = item.extend_msg[5] as usize;
    // 获取src_slot
    let src_root_lu_ret = tcb.lookup_slot(src_root_cptr);
    if unlikely(src_root_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_cnode_syscall_with_two_slot: Invocation of invalid src root cap {:#x}.", src_root_cptr);
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let src_root_slot = unsafe {&mut *src_root_lu_ret.slot };
    let src_root_cap = src_root_slot.cap;
    // 获取src_slot
    let src_slot_lu_ret = lookup_slot_for_cnode_op(true, &src_root_cap, src_index, src_depth);
    if src_slot_lu_ret.status != exception_t::EXCEPTION_NONE {
        debug!("handle_async_cnode_syscall_with_two_slot: CNode operation: Src Target slot invalid.");
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    let src_slot = convert_to_mut_type_ref::<cte_t>(src_slot_lu_ret.slot as usize);
    if src_slot.cap.get_cap_type() == CapTag::CapNullCap {
        debug!("handle_async_cnode_syscall_with_two_slot: CNode operation: Source empty.");
        return exception_t::EXCEPTION_SYSCALL_ERROR;
    }
    match label {
        AsyncMessageLabel::CNodeCopy => {
            let cap_right_word = item.extend_msg[6] as usize;
            let cap_right = seL4_CapRights_t::from_word(cap_right_word);
            invoke_cnode_copy(src_slot, dest_slot, cap_right)
        }
        AsyncMessageLabel::CNodeMint => {
            // CapRight
            let cap_right_word = item.extend_msg[6] as usize;
            let cap_right = seL4_CapRights_t::from_word(cap_right_word);
            // Badge
            let badge = item.extend_msg[7] as usize;
            invoke_cnode_mint(src_slot, dest_slot, cap_right, badge)
        }
        AsyncMessageLabel::CNodeMove => {
            invoke_cnode_move(src_slot, dest_slot)
        }
        AsyncMessageLabel::CNodeMutate => {
            let cap_data = item.extend_msg[6] as usize;
            invoke_cnode_mutate(src_slot, dest_slot, cap_data)
        }
        _ => exception_t::EXCEPTION_SYSCALL_ERROR
    }
}

fn handle_async_cnode_delete(dest_slot: &mut cte_t) -> exception_t{
    dest_slot.delete_all(true)
}

fn handle_async_page_table_map(item: &mut IPCItem, tcb: &mut tcb_t) {
    // service
    let service_cptr = item.extend_msg[0] as usize;
    // 根据service的CPtr获取slot
    let service_lu_ret = tcb.lookup_slot(service_cptr);
    if unlikely(service_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_page_table_map: Invocation of invalid service cap {:#x}.", service_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let service_slot: &mut cte_t = unsafe {&mut *service_lu_ret.slot };
    let service_cap = &mut service_slot.cap;
    // lvl1pt
    let lvl1pt_cptr = item.extend_msg[1] as usize;
    // 根据lvl1pt的CPtr获取slot
    let lvl1pt_lu_ret = tcb.lookup_slot(lvl1pt_cptr);
    if unlikely(lvl1pt_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_page_table_map: Invocation of invalid lvl1pt cap {:#x}.", lvl1pt_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let lvl1pt_slot: &mut cte_t = unsafe {&mut *lvl1pt_lu_ret.slot };
    let lvl1pt_cap = &lvl1pt_slot.cap;

    if unlikely(service_cap.get_pt_is_mapped() != 0) {
        debug!("handle_async_page_table_map: RISCVPageTable: PageTable is already mapped.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }

    let vaddr: usize = (item.extend_msg[2] as usize) << 12;
    if unlikely(vaddr >= USER_TOP) {
        debug!("handle_async_page_table_map: RISCVPageTableMap: Virtual address cannot be in kernel window.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }

    if let Some((lvl1pt, asid)) = get_vspace(lvl1pt_cap) {
        let lu_ret = lvl1pt.lookup_pt_slot(vaddr);
        let lu_slot = convert_to_mut_type_ref::<pte_t>(lu_ret.ptSlot as usize);
        // debug!("lu_ret.ptBitsLeft: {}", lu_ret.ptBitsLeft);
        if lu_ret.ptBitsLeft == seL4_PageBits || lu_slot.get_vaild() != 0 {
            debug!("handle_async_page_table_map: RISCVPageTableMap: All objects mapped at this address");
            item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
            return;
        }
        let error = invoke_page_table_map(service_cap, lu_slot, asid, vaddr & !MASK!(lu_ret.ptBitsLeft));
        if error != exception_t::EXCEPTION_NONE {
            debug!("handle_async_page_table_map: invoke error");
            item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
            return;
        } else {
            item.extend_msg[0] = AsyncErrorLabel::NoError.into();
            return;
        }
    } else {
        debug!("handle_async_page_table_map: RISCVPageTableMap: cannot get vspace.");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }   
}

fn handle_async_page_table_unmap(item: &mut IPCItem, tcb: &mut tcb_t) {
    // service
    let service_cptr = item.extend_msg[0] as usize;
    // 根据service的CPtr获取slot
    let service_lu_ret = tcb.lookup_slot(service_cptr);
    if unlikely(service_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_page_table_unmap: Invocation of invalid service cap {:#x}.", service_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let service_slot: &mut cte_t = unsafe {&mut *service_lu_ret.slot };
    // translate
    if !service_slot.is_final_cap() {
        debug!("handle_async_page_table_unmap: RISCVPageTableUnmap: cannot unmap if more than once cap exists");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let cap = &mut service_slot.cap;
    if cap.get_pt_is_mapped() != 0 {
        let asid = cap.get_pt_mapped_asid();
        let find_ret = find_vspace_for_asid(asid);
        let pte_ptr = cap.get_pt_base_ptr() as *mut pte_t;
        if find_ret.status == exception_t::EXCEPTION_NONE && find_ret.vspace_root.unwrap() == pte_ptr {
            debug!("RISCVPageTableUnmap: cannot call unmap on top level PageTable");
            item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
            return;
        }
    }
    
    let error = invoke_page_table_unmap(cap);
    if error != exception_t::EXCEPTION_NONE {
        debug!("handle_async_page_table_unmap: invoke error");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
    } else {
        item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    }
    return;
}

fn handle_async_page_map(item: &mut IPCItem, tcb: &mut tcb_t) {
    debug!("enter async_page_map handler");
    // service
    let frame_cptr = item.extend_msg[0] as usize;
    // 根据service的CPtr获取slot
    let frame_lu_ret = tcb.lookup_slot(frame_cptr);
    if unlikely(frame_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_page_table_map: Invocation of invalid frame cap {:#x}.", frame_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let frame_slot: &mut cte_t = unsafe {&mut *frame_lu_ret.slot };
    // lvl1pt
    let lvl1pt_cptr = item.extend_msg[1] as usize;
    // 根据service的CPtr获取slot
    let lvl1pt_lu_ret = tcb.lookup_slot(lvl1pt_cptr);
    if unlikely(lvl1pt_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_page_map: Invocation of invalid lvl1pt cap {:#x}.", lvl1pt_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let lvl1pt_slot: &mut cte_t = unsafe {&mut *lvl1pt_lu_ret.slot };
    let lvl1pt_cap = lvl1pt_slot.cap;
    // 其他
    let vaddr: usize = (item.extend_msg[2] as usize) << 12;
    debug!("handle_async_page_map: vaddr: {:#x}", vaddr);
    let w_rights_mask = item.extend_msg[3] as usize;
    let attr = vm_attributes_t::from_word(item.extend_msg[4] as usize);
    if let Some((lvl1pt, asid)) = get_vspace(&lvl1pt_cap) {
        let frame_size = frame_slot.cap.get_frame_size();
        let vtop = vaddr + BIT!(pageBitsForSize(frame_size)) - 1;
        if unlikely(vtop >= USER_TOP) {
            debug!("handle_async_page_map: vtop is greater than user top");
            item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
            return;
        }

        if unlikely(!checkVPAlignment(frame_size, vaddr)) {
            debug!("handle_async_page_map: frame no align");
            item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
            return;
        }

        let lu_ret = lvl1pt.lookup_pt_slot(vaddr);
        if lu_ret.ptBitsLeft != pageBitsForSize(frame_size) {
            debug!("handle_async_page_map: ptBitLeft != pageBitsForSize");
            item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
            return;
        }

        let pt_slot = convert_to_mut_type_ref::<pte_t>(lu_ret.ptSlot as usize);
        let frame_asid = frame_slot.cap.get_frame_mapped_asid();
        if frame_asid != asidInvalid {
            if frame_asid != asid {
                debug!("handle_async_page_map: RISCVPageMap: Attempting to remap a frame that does not belong to the passed address space");
                item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
                return;
            }

            if frame_slot.cap.get_frame_mapped_address() != vaddr {
                debug!("handle_async_page_map: RISCVPageMap: attempting to map frame into multiple addresses");
                item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
                return;
            }

            if pt_slot.is_pte_table() {
                debug!("handle_async_page_map: RISCVPageMap: no mapping to remap.");
                item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
                return;
            }
        } else {
            if pt_slot.get_vaild() != 0 {
                debug!("handle_async_page_map: Virtual address already mapped");
                item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
                return;
            }
        }
        let error = invoke_page_map(&mut frame_slot.cap.clone(), w_rights_mask, vaddr, asid, attr, pt_slot, frame_slot);
        if error != exception_t::EXCEPTION_NONE {
            debug!("handle_async_page_map: invoke error");
            item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        } else {
            item.extend_msg[0] = AsyncErrorLabel::NoError.into();
        }
    } else {
        debug!("handle_async_page_map: cannot get vspace");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
    }
}

fn handle_async_page_unmap(item: &mut IPCItem, tcb: &mut tcb_t) {
    // service
    let service_cptr = item.extend_msg[0] as usize;
    // 根据service的CPtr获取slot
    let service_lu_ret = tcb.lookup_slot(service_cptr);
    if unlikely(service_lu_ret.status != exception_t::EXCEPTION_NONE) {
        debug!("handle_async_page_table_map: Invocation of invalid service cap {:#x}.", service_cptr);
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
        return;
    }
    let service_slot: &mut cte_t = unsafe {&mut *service_lu_ret.slot };
    // translate
    let error = invoke_page_unmap(service_slot);
    if error != exception_t::EXCEPTION_NONE {
        debug!("handle_async_page_unmap: invoke error");
        item.extend_msg[0] = AsyncErrorLabel::SyscallError.into();
    } else {
        item.extend_msg[0] = AsyncErrorLabel::NoError.into();
    }
}


fn get_vspace(lvl1pt_cap: &cap_t) -> Option<(&mut pte_t, usize)> {
    if lvl1pt_cap.get_cap_type() != CapTag::CapPageTableCap || lvl1pt_cap.get_pt_is_mapped() == asidInvalid {
        debug!("get_vspace: RISCVMMUInvocation: Invalid top-level PageTable.");
        return None;
    }

    let lvl1pt = convert_to_mut_type_ref::<pte_t>(lvl1pt_cap.get_pt_base_ptr());
    let asid = lvl1pt_cap.get_pt_mapped_asid();

    let find_ret = find_vspace_for_asid(asid);
    if find_ret.status != exception_t::EXCEPTION_NONE {
        debug!("get_vspace: RISCVMMUInvocation: ASID lookup failed");
        return None;
    }
    if find_ret.vspace_root.unwrap() as usize != lvl1pt.get_ptr() {
        debug!("get_vspace: RISCVMMUInvocation: ASID lookup failed");
        return None;
    }
    Some((lvl1pt, asid))
}