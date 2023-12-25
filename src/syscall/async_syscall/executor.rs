extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use spin::Mutex;
use core::alloc::{GlobalAlloc, Layout};
use core::future::Future;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use core::task::Poll::{Pending, Ready};
use buddy_system_allocator::Heap;
use log::debug;
use crate::common::utils::convert_to_mut_type_ref;
use crate::{ROUND_DOWN, ROUND_UP};


pub static mut HEAP: usize = 0;

struct Global;

#[global_allocator]
static GLOBAL: Global = Global;

unsafe impl GlobalAlloc for Global {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        convert_to_mut_type_ref::<Heap>(HEAP).alloc(layout).ok()
            .map_or(0 as *mut u8, |allocation| allocation.as_ptr())
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        convert_to_mut_type_ref::<Heap>(HEAP).dealloc(NonNull::new_unchecked(ptr), layout)
    }
}


#[derive(Eq, PartialEq, Debug, Clone, Copy, Hash, Ord, PartialOrd)]
pub struct CoroutineId(pub usize);

impl CoroutineId {
    /// 生成新的协程 Id
    pub fn generate() -> CoroutineId {
        // 任务编号计数器，任务编号自增
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        if id > usize::MAX / 2 {
            // TODO: 不让系统 Panic
            panic!("too many tasks!")
        }
        CoroutineId(id)
    }
    /// 根据 usize 生成协程 Id
    pub fn from_val(v: usize) -> Self {
        Self(v)
    }
    /// 获取协程 Id 的 usize
    pub fn get_val(&self) -> usize {
        self.0
    }
}


#[derive(Debug)]
pub struct CWaker {
    cid: CoroutineId,
    pub executor: usize,
    pub next: usize,
    pub prev: usize,
}

impl CWaker {
    #[inline]
    pub fn get_ptr(&mut self) -> usize {
        self as *const CWaker as usize
    }
}

impl CWaker {
    pub fn from(value: &Waker) -> &mut Self {
        unsafe {
            convert_to_mut_type_ref::<CWaker>(value.as_raw().data() as usize)
        }
    }

    pub fn raw_wake(&mut self) {
        convert_to_mut_type_ref::<Executor>(self.executor).wake(self.cid);
    }
}

impl Wake for CWaker {
    fn wake(self: Arc<Self>) {
        convert_to_mut_type_ref::<Executor>(self.executor).wake(self.cid);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        convert_to_mut_type_ref::<Executor>(self.executor).wake(self.cid);
    }
}

struct Coroutine {
    pub cid: CoroutineId,
    future: Mutex<Pin<Box<dyn Future<Output=()> + 'static + Send + Sync>>>,
    pub waker: Arc<CWaker>
}

impl Coroutine {
    pub fn execute(self: Arc<Self>) -> Poll<()> {
        let waker = Waker::from(self.waker.clone());
        let mut context = Context::from_waker(&waker);
        self.future.lock().as_mut().poll(&mut context)
    }

    pub fn new(future: Pin<Box<dyn Future<Output=()> + 'static + Send + Sync>>, executor: &Executor) -> Arc<Self> {
        let cid = CoroutineId::generate();
        Arc::new(
            Coroutine{
                cid,
                future: Mutex::new(future),
                waker: Arc::new(CWaker {
                    cid,
                    executor: executor as *const Executor as usize,
                    next: 0,
                    prev: 0,
                })
            }
        )
    }
}

pub struct Executor {
    heap_ptr: usize,
    pub thread: usize,
    tasks: BTreeMap<CoroutineId, Arc<Coroutine>>,
    ready_queue: Vec<CoroutineId>,
}

impl Executor {
    fn set_heap(&self) {
        unsafe {
            HEAP = self.heap_ptr;
        }
    }
    pub fn init(&mut self, heap_ptr: usize, heap_end: usize) -> bool {
        // debug!("executor init: {:#x}", self as *const Self as usize);
        let heap_start = ROUND_UP!(heap_ptr + core::mem::size_of::<Heap>(), 3);
        let heap_end = ROUND_DOWN!(heap_end, 3);
        // debug!("{:#x} {:#x}", heap_start, heap_end);
        if heap_end < heap_start {
            return false;
        }
        let local_allocator = convert_to_mut_type_ref::<Heap>(heap_ptr);

        unsafe { local_allocator.init(heap_start, heap_end - heap_start); }
        self.heap_ptr = heap_ptr;
        self.tasks = BTreeMap::new();
        self.ready_queue = Vec::new();
        true
    }

    pub fn execute(&mut self) -> bool {
        self.set_heap();
        while let Some(cid) = self.ready_queue.pop() {
            if let Some(task) = self.tasks.get(&cid) {
                if let Ready(_) = task.clone().execute() {
                    // todo: bugs need to fix
                    self.tasks.remove(&cid);
                }
            } else {
                panic!("get invalid task! cid: {:?}", cid);
            }
        }
        if self.tasks.is_empty() {
            return true;
        }
        false
    }

    pub fn set_block_thread(&mut self, thread: usize) {
        self.thread = thread;
    }

    pub fn spawn(&mut self, future: impl Future<Output=()> + 'static + Send + Sync) {

        self.set_heap();
        let task = Coroutine::new(Box::pin(future), self);
        // debug!("spawn: self heap: {}, cid: {:?}", self.heap_ptr, task.cid);

        self.tasks.insert(task.cid, task.clone());
        self.ready_queue.push(task.cid);
    }

    pub fn wake(&mut self, cid: CoroutineId) {
        self.set_heap();
        self.ready_queue.push(cid);
    }
}