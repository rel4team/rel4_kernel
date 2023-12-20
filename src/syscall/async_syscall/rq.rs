use crate::common::sel4_config::seL4_MsgMaxExtraCaps;

pub const MAX_ITEM_LEN: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ReqItem {
    pub syscall_id: isize,
    pub dest_cptr: usize,
    pub msg_registers: [usize; MAX_ITEM_LEN - 9],
    pub userData: usize,
    pub caps_or_badges: [usize; seL4_MsgMaxExtraCaps],
    pub receiveCNode: usize,
    pub receiveIndex: usize,
    pub receiveDepth: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ResItem {
    pub msg_registers: [usize; MAX_ITEM_LEN],
}

pub struct ReqBuffer {
    pub req_queue: [ReqItem; 512 / MAX_ITEM_LEN - 1],
}

pub struct ResBuffer {
    pub res_queue: [ResItem; 512 / MAX_ITEM_LEN - 1],
}