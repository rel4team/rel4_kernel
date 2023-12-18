use crate::common::sel4_config::{seL4_MsgMaxExtraCaps, seL4_MsgMaxLength};

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


// #[repr(C)]
// #[derive(Copy, Clone)]
// pub struct seL4_IPCBuffer {
//     pub uintrFlag: usize,
//     pub tag: usize,
//     pub msg: [usize; seL4_MsgMaxLength],
//     pub userData: usize,
//     pub caps_or_badges: [usize; seL4_MsgMaxExtraCaps],
//     pub receiveCNode: usize,
//     pub receiveIndex: usize,
//     pub receiveDepth: usize,
// }

pub struct ReqBuffer {
    pub uintrFlag: usize,
    pub tag: usize,
    pub padding: [usize; MAX_ITEM_LEN - 2],
    pub req_queue: [usize; 512 / MAX_ITEM_LEN - 1],
}

pub struct ResBuffer {
    pub uintrFlag: usize,
    pub padding: [usize; MAX_ITEM_LEN - 1],
    pub res_queue: [usize; 512 / MAX_ITEM_LEN - 1],
}