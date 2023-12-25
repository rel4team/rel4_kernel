use alloc::task::Wake;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::task::Poll::{Pending, Ready};
use log::debug;
use crate::common::utils::convert_to_mut_type_ref;
use crate::cspace::interface::cap_t;
use crate::syscall::async_syscall::Executor;
use crate::syscall::async_syscall::executor::CWaker;
use crate::syscall::async_syscall::ipc::EndpointOperator::Call;
use crate::task_manager::ipc::{endpoint_t, EPState};
use crate::task_manager::ipc::EPState::{Idle, Recv, Send};
use crate::task_manager::{set_thread_state, tcb_t};
use crate::task_manager::ThreadState::ThreadStateRunning;

#[derive(Eq, PartialEq, Copy, Clone)]
pub enum EndpointOperator {
    Send,
    Recv,
    Call,
}

pub struct EndpointFuture {
    pub ep_cap: cap_t,
    pub operator: EndpointOperator,
    pub ready_for_next: bool
}

impl Future for EndpointFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.ready_for_next == true {
            return Ready(())
        }
        let ep = convert_to_mut_type_ref::<endpoint_t>(self.ep_cap.get_ep_ptr());
        match ep.get_state() {
            EPState::Idle => {
                let waker = cx.waker();
                let mut queue = ep.get_queue();
                queue.ep_append_waker(CWaker::from(waker));
                match self.operator {
                    EndpointOperator::Send | EndpointOperator::Call => {
                        ep.set_state(Send as usize);
                    }
                    _ => {
                        ep.set_state(Recv as usize);
                    }
                }
                ep.set_queue(&queue);
                self.ready_for_next = true;
                return Pending;
            }
            EPState::Send => {
                if self.operator == EndpointOperator::Recv {
                    let mut queue = ep.get_queue();
                    let sender = convert_to_mut_type_ref::<CWaker>(queue.head);
                    queue.ep_dequeue_waker(sender);
                    ep.set_queue(&queue);
                    if queue.empty() {
                        ep.set_state(Idle as usize);
                    }
                    sender.raw_wake();
                    let executor = convert_to_mut_type_ref::<Executor>(sender.executor);
                    if executor.execute() {
                        // todo: need to wakeup thread
                        let thread = convert_to_mut_type_ref::<tcb_t>(executor.thread);
                        set_thread_state(thread, ThreadStateRunning);
                        thread.sched_enqueue();
                    }
                }

                if self.operator == EndpointOperator::Send || self.operator == Call {
                    let mut queue = ep.get_queue();
                    let waker = cx.waker();
                    queue.ep_append_waker(CWaker::from(waker));
                    ep.set_queue(&queue);
                    return Pending;
                }
            }
            EPState::Recv => {
                if self.operator == EndpointOperator::Send {
                    let mut queue = ep.get_queue();
                    let receiver = convert_to_mut_type_ref::<CWaker>(queue.head);
                    queue.ep_dequeue_waker(receiver);
                    ep.set_queue(&queue);
                    receiver.raw_wake();
                    let executor = convert_to_mut_type_ref::<Executor>(receiver.executor);
                    if executor.execute() {
                        let thread = convert_to_mut_type_ref::<tcb_t>(executor.thread);
                        set_thread_state(thread, ThreadStateRunning);
                        thread.sched_enqueue();
                    }
                    if queue.empty() {
                        ep.set_state(Idle as usize);
                    }

                }
                if self.operator == EndpointOperator::Recv {
                    let mut queue = ep.get_queue();
                    let waker = cx.waker();
                    queue.ep_append_waker(CWaker::from(waker));
                    ep.set_queue(&queue);
                    return Pending;
                }
            }
        }
        return Poll::Ready(())
    }
}
