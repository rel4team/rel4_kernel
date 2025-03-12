use crate::async_runtime::coroutine::{Coroutine, CoroutineId};
use crate::common::utils::cpu_id;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;
use log::debug;
use taic_driver::{LocalQueue, Taic};
use crate::taic_test::TAIC;

// const TAIC_BASE: usize = axconfig::PHYS_VIRT_OFFSET + axconfig::MMIO_REGIONS[1].0;
// const LQ_NUM: usize = 8;
// const TAIC: Taic = Taic::new(TAIC_BASE, LQ_NUM);

pub struct Executor {
    pub tasks: BTreeMap<CoroutineId, Arc<Coroutine>>, //map: cid-coroutine
    pub current: Option<CoroutineId>,                 //当前运行着的协程
    pub immediate_value: BTreeMap<CoroutineId, u64>,  //应该和调度抢断有关，还未知
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
    pub fn lq_init(&mut self) {
        // let lq0 = Arc::new(TAIC.alloc_lq(1, 0).unwrap());
        // lq0.task_enqueue(6);
        self.ready_queue = Some(Arc::new(TAIC.alloc_lq(1, 2).unwrap()));
        // let lq2 = Arc::new(TAIC.alloc_lq(1, 3).unwrap());
        // lq2.task_enqueue(5);
        // if let Some(task)= self.ready_queue.as_ref().unwrap().task_dequeue(){
        //     debug!("get task id: {:?}", task);
        // }

        // self.ready_queue.as_ref().unwrap().whart(cpu_id());
    }


    pub fn lq_register_receiver(&mut self, sender_idx: usize, handler: usize) {
        self.ready_queue
            .as_ref()
            .unwrap()
            .register_receiver(1, sender_idx, handler);
    }
    pub fn lq_register_sender(&mut self, recv_idx: usize) {
        self.ready_queue
            .as_ref()
            .unwrap()
            .register_sender(1, recv_idx);
    }
    pub fn lq_send_signal(&mut self, recv_idx: usize) {
        self.ready_queue
            .as_ref()
            .unwrap()
            .send_intr(1, recv_idx);
    }

    pub fn spawn(
        &mut self,
        future: Pin<Box<dyn Future<Output = ()> + 'static + Send + Sync>>,
    ) -> CoroutineId {
        let task = Coroutine::new(future);
        let cid = task.cid;
        // self.ready_queue.push_back(cid);
        self.ready_queue
            .as_ref()
            .unwrap()
            .task_enqueue(cid.0 as usize);
        self.tasks.insert(cid, task);
        debug!("[async executer] spawn task , cid: {:?}", cid);
        return cid;
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub fn fetch(&mut self) -> Option<Arc<Coroutine>> {
        //尝试取task
        if let Some(taskid) = self.ready_queue.as_ref().unwrap().task_dequeue() {
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
        self.ready_queue
            .as_ref()
            .unwrap()
            .task_enqueue(cid.0 as usize);
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
            debug!("[fetched] task cid: {:?}", cid);
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
