use log::debug;
use crate::async_runtime::new_buffer::NewBuffer;
use crate::async_runtime::utils::yield_now;
use crate::common::utils::convert_to_mut_type_ref;
use crate::cspace::interface::cap_t;
use crate::task_manager::tcb_t;

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