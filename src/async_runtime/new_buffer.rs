use crate::async_runtime::coroutine::CoroutineId;
use crate::async_runtime::utils::BitMap64;

pub const MAX_ITEM_NUM: usize = 64;
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IPCItem {
    pub cid: CoroutineId,
    pub msg_info: u32,
    pub extend_msg: [u16; 8],
}

impl IPCItem {
    pub const fn new() -> Self {
        Self {
            cid: CoroutineId(0),
            msg_info: 0,
            extend_msg: [0u16; 8],
        }
    }

    pub fn from(cid: CoroutineId, msg: u32) -> Self {
        Self {
            cid,
            msg_info: msg,
            extend_msg: [0u16; 8],
        }
    }
}

pub struct ItemsQueue {
    pub bitmap: BitMap64,
    pub items: [IPCItem; MAX_ITEM_NUM],
}


impl ItemsQueue {
    pub const fn new() -> Self {
        Self {
            bitmap: BitMap64::new(),
            items: [IPCItem::new(); MAX_ITEM_NUM]
        }
    }

    #[inline]
    pub fn write_free_item(&mut self, item: &IPCItem) -> Result<(), ()> {
        let index = self.bitmap.find_first_zero();
        // sel4::debug_println!("[write_free_item] index: {}", index);
        return {
            if index < MAX_ITEM_NUM {
                self.items[index] = item.clone();
                self.bitmap.set(index);
                Ok(())
            } else {
                Err(())
            }
        }
    }
    #[inline]
    pub fn get_first_item(&mut self) -> Option<IPCItem> {
        let index = self.bitmap.find_first_one();
        // sel4::debug_println!("[get_first_item] index: {}", index);
        return {
            if index < MAX_ITEM_NUM {
                let ans = Some(self.items[index]);
                self.bitmap.clear(index);
                ans
            } else {
                None
            }
        }
    }
}

#[repr(align(4096))]
pub struct NewBuffer {
    pub recv_req_status: bool,
    pub recv_reply_status: bool,
    pub req_items: ItemsQueue,
    pub res_items: ItemsQueue,
}

impl NewBuffer {
    pub const fn new() -> Self {
        Self {
            recv_req_status: false,
            recv_reply_status: false,
            req_items: ItemsQueue::new(),
            res_items: ItemsQueue::new(),
        }
    }
}


pub struct NewBufferMap {
    pub buf: &'static NewBuffer,
    pub cid: CoroutineId,
}