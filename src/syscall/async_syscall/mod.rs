mod executor;
mod rq;

use log::debug;
pub use executor::Executor;
use crate::common::message_info::MessageLabel;
use crate::common::message_info::MessageLabel::ExecutorExecute;
use crate::common::structures::{exception_t, seL4_IPCBuffer};
use crate::common::utils::{convert_to_mut_type_ref, convert_to_type_ref};
use crate::cspace::interface::{cap_t, cte_t};
use crate::syscall::async_syscall::rq::ReqBuffer;
use crate::task_manager::{get_currenct_thread, set_thread_state};
use crate::task_manager::ThreadState::{ThreadStateBlockedOnExecutor, ThreadStateRestart};

pub fn decode_executor_invocation(label: MessageLabel, length: usize, slot: &mut cte_t, cap: &cap_t, cap_index: usize,
                                  block: bool, call: bool, buffer: Option<&seL4_IPCBuffer>) ->exception_t {
    if label == ExecutorExecute {
        if buffer.is_none() {
            debug!("no buffer for executor, do nothing");
            return exception_t::EXCEPTION_NONE;
        }
        let executor = convert_to_mut_type_ref::<Executor>(cap.get_executor_ptr());
        let req_buffer = convert_to_type_ref::<ReqBuffer>(buffer.unwrap() as *const seL4_IPCBuffer as usize);
        register_syscall_task(executor, req_buffer);
        set_thread_state(get_currenct_thread(), ThreadStateRestart);
        if !executor.execute() {
            set_thread_state(get_currenct_thread(), ThreadStateBlockedOnExecutor);
        }
    }

    exception_t::EXCEPTION_NONE
}

fn register_syscall_task(executor: &mut Executor, req_buffer: &ReqBuffer) {

}