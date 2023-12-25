mod executor;
mod rq;
mod ipc;


use core::future::Future;
use core::intrinsics::unlikely;

use log::debug;
pub use executor::{Executor, CWaker};

use crate::common::message_info::MessageLabel;
use crate::common::message_info::MessageLabel::ExecutorExecute;
use crate::common::sel4_config::seL4_TruncatedMessage;
use crate::common::structures::{exception_t, seL4_IPCBuffer};
use crate::common::utils::{convert_to_mut_type_ref, convert_to_type_ref};
use crate::cspace::interface::{cap_t, CapTag, cte_t};
use crate::kernel::boot::{get_extra_cap_by_index, current_syscall_error};
use crate::syscall::async_syscall::ipc::{EndpointFuture, EndpointOperator};
use crate::syscall::async_syscall::rq::{ReqBuffer, MAX_ITEM_LEN, ResItem, ReqItem};
use crate::task_manager::{get_currenct_thread, set_thread_state};
use crate::task_manager::ThreadState::{ThreadStateBlockedOnExecutor, ThreadStateRestart};

use self::rq::ResBuffer;

use super::{get_syscall_arg, SysRecv, SysSend};

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
        let req_buffer_cap = get_extra_cap_by_index(0).unwrap().cap;
        let res_buffer_cap = get_extra_cap_by_index(1).unwrap().cap;
        let req_buffer = convert_to_type_ref::<ReqBuffer>(req_buffer_cap.get_frame_base_ptr());
        let res_buffer = convert_to_mut_type_ref::<ResBuffer>(res_buffer_cap.get_frame_base_ptr());

        let req_num = get_syscall_arg(0, buffer);
        register_syscall_tasks(executor, req_buffer, res_buffer, req_num);
        set_thread_state(get_currenct_thread(), ThreadStateRestart);
        if !executor.execute() {
            // debug!("blocked thread: {:#x}", get_currenct_thread().get_ptr());
            executor.set_block_thread(get_currenct_thread().get_ptr());
            set_thread_state(get_currenct_thread(), ThreadStateBlockedOnExecutor);
        }
    }

    exception_t::EXCEPTION_NONE
}

fn register_syscall_tasks(executor: &mut Executor, req_buffer: &ReqBuffer, res_buffer: &mut ResBuffer, req_num: usize) {
    assert!(req_num < 512 / MAX_ITEM_LEN - 1);
    for i in 0..req_num {
        let req = &req_buffer.req_queue[i];
        let res_slot = res_buffer.res_queue.get_mut(i).unwrap();
        if let Some(task) = get_async_syscall_task(req, res_slot) {
            executor.spawn(task);
        } else {
            debug!("invalid task");
        }
    }
}

fn get_async_syscall_task(req: &ReqItem, res_slot: &mut ResItem) -> Option<impl Future<Output=()> + 'static + Send + Sync> {
    // debug!("req item: {:?}", req);
    if req.syscall_id == SysSend || req.syscall_id == SysRecv  {
        let current = get_currenct_thread();
        let lu_ret = current.lookup_slot(req.dest_cptr);
        if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
            debug!("Invocation of invalid cap {:#x}.", req.dest_cptr);
            return None;
        }
        let cap = unsafe {(*(lu_ret.slot)).cap};
        if cap.get_cap_type() != CapTag::CapEndpointCap {
            debug!("Invocation of invalid cap type {:?}.", cap.get_cap_type());
            return None;
        }
        let async_ep = if req.syscall_id == SysSend{
            EndpointFuture {ep_cap: cap, operator: EndpointOperator::Send, ready_for_next: false}
        } else {
            EndpointFuture {ep_cap: cap, operator: EndpointOperator::Recv, ready_for_next: false}
        };
        return Some(
            async {
                async_ep.await
            }
        );
    }
    None
}
