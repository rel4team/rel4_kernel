use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use log::debug;
use crate::async_runtime::coroutine::CoroutineId;
use crate::async_runtime::executor::Executor;

mod coroutine;
mod new_buffer;
mod executor;
mod async_syscall_handler;
mod utils;

pub use async_syscall_handler::async_syscall_handler;
pub use new_buffer::{NewBufferMap, NewBuffer};

pub static mut NEW_BUFFER_MAP: Vec<NewBufferMap> = Vec::new();

static mut EXECUTOR: Executor = Executor::new();

#[inline]
pub fn coroutine_spawn(future: Pin<Box<dyn Future<Output=()> + 'static + Send + Sync>>) -> CoroutineId {
    unsafe {
        EXECUTOR.spawn(future)
    }
}

#[inline]
pub fn coroutine_wake(cid: &CoroutineId) {
    unsafe {
        EXECUTOR.wake(cid);
    }
}

#[inline]
pub fn coroutine_wake_with_value(cid: &CoroutineId, value: u64) {
    unsafe {
        EXECUTOR.immediate_value.insert(*cid, value);
        EXECUTOR.wake(cid);
    }
}

#[inline]
pub fn coroutine_get_immediate_value(cid: &CoroutineId) -> Option<u64> {
    unsafe {
        EXECUTOR.immediate_value.remove(cid)
    }
}

#[inline]
pub fn coroutine_get_current() -> CoroutineId {
    unsafe {
        EXECUTOR.current.unwrap()
    }
}

#[inline]
pub fn get_executor_ptr() -> usize {
    unsafe {
        &EXECUTOR as *const Executor as usize
    }
}

#[inline]
pub fn coroutine_run_until_blocked() {
    unsafe {
        EXECUTOR.run_until_blocked()
    }
}


#[inline]
pub fn coroutine_run_until_complete() {
    unsafe {
        EXECUTOR.run_until_complete()
    }
}