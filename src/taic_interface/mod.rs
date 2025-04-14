mod irq_allocator;

use alloc::sync::Arc;
use lazy_static::lazy_static;
use taic_driver::{LocalQueue, Taic};

use self::irq_allocator::IRQ_ALLOCATOR;

//TAIC
const TAIC_BASE: usize = axconfig::PHYS_VIRT_OFFSET + axconfig::MMIO_REGIONS[1].0;
const LQ_NUM: usize = 8;
const TAIC: Taic = Taic::new(TAIC_BASE, LQ_NUM);

const OS_ID: usize = 1;
const PROCESS_ID: usize = 0;

// kernel taic local queue
lazy_static! {
    static ref LOCAL_QUEUE: Arc<LocalQueue> = {
        let lq = TAIC
            .alloc_lq(OS_ID, PROCESS_ID)
            .expect("[TAIC] Failed to allocate local queue");
        Arc::new(lq)
    };
}

#[inline]
pub fn get_lq() -> Arc<LocalQueue> {
    LOCAL_QUEUE.clone()
}

/**
 * @description: 将内核队列注册成信号的接收者
 * @param {usize} send_idx    发送信号的进程id
 * @param {usize} irq         接收信号的channel
 * @param {usize} handler
*/
#[inline]
pub fn register_receiver(
    sender_idx: usize,
    irq: usize,
    handler: usize,
    preempt: bool,
    reusable: bool,
) {
    let _handler = handler << 2 | ((reusable as usize) << 1) | (preempt as usize);
    LOCAL_QUEUE.register_receiver(1, sender_idx, irq, _handler);
}

/**
 * @description: 将内核队列注册成信号的发送者
 * @param {usize} recv_idx    接收信号的进程id
 * @param {usize} irq         发送信号的channel
*/
#[inline]
pub fn register_sender(recv_idx: usize, irq: usize) {
    LOCAL_QUEUE.register_sender(OS_ID, recv_idx, irq);
}

#[inline]
pub fn send_signal(recv_idx: usize, irq: usize) {
    LOCAL_QUEUE.send_intr(OS_ID, recv_idx, irq);
}

// #[inline]
// pub fn alloc_vec() -> Option<usize> {
//     unsafe { IRQ_ALLOCATOR.alloc() }
// }

// #[inline]
// pub fn free_vec(vec: usize) {
//     unsafe {
//         IRQ_ALLOCATOR.free(vec);
//     }
// }
