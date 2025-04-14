use crate::async_runtime::coroutine::{Coroutine, CoroutineId};
use crate::common::utils::cpu_id;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;
use log::debug;
use taic_driver::LocalQueue;

pub struct Executor {
    pub tasks: BTreeMap<CoroutineId, Arc<Coroutine>>, //map: cid-coroutine
    pub current: Option<CoroutineId>,                 //当前运行着的协程
    pub immediate_value: BTreeMap<CoroutineId, u64>,
    // pub ready_queue: VecDeque<CoroutineId>,
    pub ready_queue: Option<Arc<LocalQueue>>, //当前就绪的队列
    pub pending_set: BTreeSet<CoroutineId>,   //pending的集合
}

impl Executor {

    pub const fn new() -> Self {
        Self {
            current: None,
            tasks: BTreeMap::new(),
            immediate_value: BTreeMap::new(),
            ready_queue: None,
            pending_set: BTreeSet::new(),
        }
    }

    #[inline]
    pub fn init(&mut self ,lq:Arc<LocalQueue>){
        self.ready_queue = Some(lq);
    }

    pub fn spawn(
        &mut self,
        future: Pin<Box<dyn Future<Output = ()> + 'static + Send + Sync>>,
    ) -> CoroutineId {
        let task = Coroutine::new(future);
        let cid = task.cid;
        // self.ready_queue.push_back(cid);
        self.ready_queue.as_ref().unwrap().task_enqueue((cid.0 as usize) << 2);
        self.tasks.insert(cid, task);
        debug!("[async executer] spawn task , cid: {:?}", cid);
        return cid;
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub fn fetch(&mut self) -> Option<Arc<Coroutine>> {
        //尝试取task
        if let Some(handler) = self.ready_queue.as_ref().unwrap().task_dequeue() {
            let taskid = handler >> 2;
            let cid = CoroutineId::from_val(taskid as u32); //taskid 转成cid({usize})
            let task = self.tasks[&cid].clone();
            self.current = Some(cid); //current 赋值
            Some(task)
        } else {
            None
        }
    }

    #[inline]
    pub fn pending(&mut self, cid: CoroutineId) {
        self.pending_set.insert(cid);
    }

    #[inline]
    pub fn is_pending(&self, cid: CoroutineId) -> bool {
        self.pending_set.contains(&cid)
    }

    pub fn wake(&mut self, cid: &CoroutineId) {
        // todo:  need to fix bugs
        // sel4::debug_println!("[wake] cid: {:?}", cid);
        assert!(self.tasks.contains_key(cid));
        self.ready_queue.as_ref().unwrap()
            .task_enqueue((cid.0 as usize)<<2);
        // self.ready_queue.push_back(*cid);
        self.pending_set.remove(cid);
    }

    #[inline]
    pub fn remove_task(&mut self, cid: CoroutineId) {
        self.tasks.remove(&cid);
    }

    #[inline]
    pub fn run_until_complete(&mut self) {
        while !self.is_empty() {
            self.run_until_blocked();
        }
    }

    pub fn run_until_blocked(&mut self) {
        while let Some(task) = self.fetch() {
            //尝试取task，返回coroutine
            let cid = task.cid;
            // debug!("[fetched] task cid: {:?}", cid);
            match task.execute() {
                Poll::Ready(_) => {
                    //运行结束，则删除task
                    self.remove_task(cid);
                }
                Poll::Pending => {
                    //阻塞，则加到pending里   ?:如果只用taic唤醒，还需要吗？
                    self.pending(cid);
                }
            }
        }
        // debug!("all async coroutine finished");
    }
}
