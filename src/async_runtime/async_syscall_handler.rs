use log::debug;
use crate::async_runtime::new_buffer::NewBuffer;
use crate::async_runtime::utils::yield_now;
use crate::common::utils::convert_to_mut_type_ref;
use crate::cspace::interface::cap_t;
use crate::task_manager::tcb_t;


// 每个线程对应一个内核syscall handler协程
// 每个线程在用户态只能发现自己的内核协程不在线
// 当线程陷入内核去激活协程时，所有的内核协程都不在线（因为内核独占）
// 线程陷入内核只是去激活协程，并不会执行协程，而是发送ipi去挑选空闲cpu来执行所有被激活的协程
    // 当没有cpu空闲时，还是等待时钟中断？
    // 当系统调用频率不够高时，仍然需要额外陷入内核，但等时钟中断的话就不会有额外的特权级切换开销
// 当前在每个核心的时钟中断时检查每个buffer的req标志位，被设置标志位的buffer对应的协程被内核主动激活并执行。
// todo：新增激活内核协程的系统调用，不需要获取内核锁，涉及到的数据安全靠自旋锁保证



pub async fn async_syscall_handler(ntfn_cap: cap_t, new_buffer_cap: cap_t, tcb: &mut tcb_t) {
    debug!("hello async_syscall_handler");
    let new_buffer = convert_to_mut_type_ref::<NewBuffer>(new_buffer_cap.get_frame_base_ptr());
    let badge = ntfn_cap.get_nf_badge();
    loop {
        if let Some(mut item) = new_buffer.req_items.get_first_item() {
            debug!("recv req: {}", item.msg_info);
            item.msg_info += 1;
            new_buffer.res_items.write_free_item(&item).unwrap();
            if new_buffer.recv_reply_status == false {
                new_buffer.recv_reply_status = true;
                // todo: send uintr
            }
        } else {
            new_buffer.recv_req_status = false;
            yield_now().await;
        }
    }
}