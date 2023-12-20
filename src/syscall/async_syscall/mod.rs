mod executor;
mod rq;

use log::debug;
pub use executor::Executor;
use crate::common::message_info::MessageLabel;
use crate::common::message_info::MessageLabel::ExecutorExecute;
use crate::common::sel4_config::seL4_TruncatedMessage;
use crate::common::structures::{exception_t, seL4_IPCBuffer};
use crate::common::utils::{convert_to_mut_type_ref, convert_to_type_ref};
use crate::cspace::interface::{cap_t, cte_t};
use crate::kernel::boot::{get_extra_cap_by_index, current_syscall_error};
use crate::syscall::async_syscall::rq::{ReqBuffer, MAX_ITEM_LEN};
use crate::task_manager::{get_currenct_thread, set_thread_state};
use crate::task_manager::ThreadState::{ThreadStateBlockedOnExecutor, ThreadStateRestart};

use self::rq::ResBuffer;

use super::get_syscall_arg;

pub fn decode_executor_invocation(label: MessageLabel, length: usize, slot: &mut cte_t, cap: &cap_t, cap_index: usize,
                                  block: bool, call: bool, buffer: Option<&seL4_IPCBuffer>) ->exception_t {
    if label == ExecutorExecute {
        if buffer.is_none() {
            debug!("no buffer for executor, do nothing");
            return exception_t::EXCEPTION_NONE;
        }
        if length < 1 || get_extra_cap_by_index(0).is_none() || get_extra_cap_by_index(1).is_none() {
            debug!("Executor operation: Truncated message.");
            unsafe { current_syscall_error._type = seL4_TruncatedMessage; }
            return exception_t::EXCEPTION_SYSCALL_ERROR;
        }
        let executor = convert_to_mut_type_ref::<Executor>(cap.get_executor_ptr());
        let req_buffer = convert_to_type_ref::<ReqBuffer>(buffer.unwrap() as *const seL4_IPCBuffer as usize);
        let req_buffer_cap = get_extra_cap_by_index(0).unwrap().cap;
        let res_buffer_cap = get_extra_cap_by_index(1).unwrap().cap;
        let req_buffer = convert_to_type_ref::<ReqBuffer>(req_buffer_cap.get_frame_base_ptr());
        let res_buffer = convert_to_mut_type_ref::<ResBuffer>(res_buffer_cap.get_frame_base_ptr());

        let req_num = get_syscall_arg(0, buffer);
        register_syscall_task(executor, req_buffer, res_buffer, 0);
        set_thread_state(get_currenct_thread(), ThreadStateRestart);
        if !executor.execute() {
            set_thread_state(get_currenct_thread(), ThreadStateBlockedOnExecutor);
        }
    }

    exception_t::EXCEPTION_NONE
}

fn register_syscall_task(executor: &mut Executor, req_buffer: &ReqBuffer, res_buffer: &mut ResBuffer, req_num: usize) {
    assert!(req_num < 512 / MAX_ITEM_LEN - 1);
    for i in 0..req_num {
        let req = &req_buffer.req_queue[i];
        let res_slot = res_buffer.res_queue.get_mut(i);
    }
}