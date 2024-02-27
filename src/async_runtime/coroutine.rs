use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};

#[derive(Eq, PartialEq, Debug, Clone, Copy, Hash, Ord, PartialOrd)]
pub struct CoroutineId(pub u32);

impl CoroutineId {
    /// 生成新的协程 Id
    pub fn generate() -> CoroutineId {
        // 任务编号计数器，任务编号自增
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        if id > u32::MAX / 2 {
            // TODO: 不让系统 Panic
            panic!("too many tasks!")
        }
        CoroutineId(id)
    }
    /// 根据 usize 生成协程 Id
    pub fn from_val(v: u32) -> Self {
        Self(v)
    }
    /// 获取协程 Id 的 usize
    pub fn get_val(&self) -> u32 {
        self.0
    }
}

struct CoroutineWaker(CoroutineId);

impl CoroutineWaker {
    /// 新建协程 waker
    pub fn new(cid: CoroutineId) -> Waker {
        Waker::from(Arc::new(Self(cid)))
    }
}

impl Wake for CoroutineWaker {
    fn wake(self: Arc<Self>) { }
    fn wake_by_ref(self: &Arc<Self>) { }
}

pub struct Coroutine{
    /// 协程编号
    pub cid: CoroutineId,
    /// future
    pub inner: RefCell<CoroutineInner>,
}

pub struct CoroutineInner {
    pub future: Pin<Box<dyn Future<Output=()> + 'static + Send + Sync>>,
    /// waker
    pub waker: Arc<Waker>,
}

impl Coroutine {
    /// 生成协程
    pub fn new(future: Pin<Box<dyn Future<Output=()> + Send + Sync>>) -> Arc<Self> {
        let cid = CoroutineId::generate();
        Arc::new(
            Coroutine {
                cid,
                inner: RefCell::new(
                    CoroutineInner {
                        future,
                        waker: Arc::new(CoroutineWaker::new(cid)),
                    }
                )

            }
        )
    }
    /// 执行
    pub fn execute(self: Arc<Self>) -> Poll<()> {
        let waker = self.inner.borrow().waker.clone();
        let mut context = Context::from_waker(&*waker);

        self.inner.borrow_mut().future.as_mut().poll(&mut context)
    }
}
