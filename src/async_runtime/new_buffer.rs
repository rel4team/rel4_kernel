use crate::async_runtime::coroutine::CoroutineId;
use crate::async_runtime::utils::{RingBuffer, SafeRingBuffer,IndexAllocator};
// use crate::utils::IndexAllocator;
use core::sync::atomic::AtomicBool;
use spin::Mutex;
// use sel4::r#yield;

pub const MAX_ITEM_NUM: usize = 4096;
pub const MAX_IPC_MSG_LEN: usize = 16;

#[repr(align(8))]
#[derive(Clone, Copy, Debug)]
pub struct IPCItem {
    pub vec: u32,
    pub cid: CoroutineId,
    pub msg_info: u32,
    pub extend_msg: [u16; MAX_IPC_MSG_LEN],
}

impl Default for IPCItem {
    fn default() -> Self {
        Self {
            vec: 0,
            cid: Default::default(),
            msg_info: 0,
            extend_msg: [0; MAX_IPC_MSG_LEN],
        }
    }
}

impl IPCItem {
    pub const fn new() -> Self {
        Self {
            vec: 0,
            cid: CoroutineId(0),
            msg_info: 0,
            extend_msg: [0u16; MAX_IPC_MSG_LEN],
        }
    }

    pub fn from(vec: u32, cid: CoroutineId, msg: u32) -> Self {
        Self {
            vec,
            cid,
            msg_info: msg,
            extend_msg: [0u16; MAX_IPC_MSG_LEN],
        }
    }
}

pub struct ItemsIdxQueue {
    buffer: SafeRingBuffer<usize, MAX_ITEM_NUM>,
}

impl ItemsIdxQueue {
    pub fn new() -> Self {
        Self {
            buffer: SafeRingBuffer::new(),
        }
    }

    #[inline]
    pub fn write_free_idx(&mut self, idx: usize) -> Result<(), ()> {
        return self.buffer.push_safe(&idx);
    }

    #[inline]
    pub fn get_first_idx(&mut self) -> Option<usize> {
        return self.buffer.pop_safe();
    }
    // #[inline]
    // pub fn write_item_at(&mut self, index: usize, item: &IPCItem) -> Result<(), ()> {
    //     self.buffer.write_at(index, *item)
    // }

    // #[inline]
    // pub fn read_item_at(&self, index: usize) -> Option<IPCItem> {
    //     self.buffer.read_at(index)
    // }
}

#[repr(align(4096))]
pub struct NewBuffer {
    pub recv_req_status: AtomicBool,
    pub recv_reply_status: AtomicBool,
    pub req_items: ItemsIdxQueue,
    pub res_items: ItemsIdxQueue,
    pub data: [IPCItem; MAX_ITEM_NUM],
    pub idx_allocator: IndexAllocator<4096>,
}

impl NewBuffer {
    pub fn new() -> Self {
        Self {
            recv_req_status: AtomicBool::new(false),
            recv_reply_status: AtomicBool::new(false),
            req_items: ItemsIdxQueue::new(),
            res_items: ItemsIdxQueue::new(),
            data:[IPCItem::default(); MAX_ITEM_NUM],
            idx_allocator:IndexAllocator::new()
        }
    }
    #[inline]
    pub fn get_ptr(&self) -> usize {
        self as *const Self as usize
    }

    #[inline]
    pub fn from_ptr(ptr: usize) -> &'static mut Self {
        unsafe { &mut *(ptr as *mut Self) }
    }

    // fn alloc_idx(&self) -> Option<usize> {
    //     self.idx_allocator.allocate()
    // }

    // fn release_idx(&self, index: usize) {
    //     self.idx_allocator.release(index);
    // }
}


// buffer map
pub struct NewBufferMap {
    pub buf: &'static mut NewBuffer,
    pub cid: CoroutineId,
}
