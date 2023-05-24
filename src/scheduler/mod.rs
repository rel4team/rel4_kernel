use crate::obj::tcb::{tcb_t, tcb_queue_t};
use crate::{config::*, BIT};

#[no_mangle]
pub static mut ksDomainTime: usize = 0;

#[no_mangle]
pub static mut ksCurDomain: usize = 0;

#[no_mangle]
pub static mut ksDomScheduleIdx: usize = 0;

#[no_mangle]
pub static mut ksCurThread: *mut tcb_t = 0 as *mut tcb_t;

#[no_mangle]
pub static mut ksIdleThread: *mut tcb_t = 0 as *mut tcb_t;

#[no_mangle]
pub static mut ksSchedulerAction: *mut tcb_t = 1 as *mut tcb_t;

#[no_mangle]
pub static mut ksReadyQueues: [tcb_queue_t; NUM_READY_QUEUES] = [tcb_queue_t {
    head: 0 as *mut tcb_t,
    tail: 0 as *mut tcb_t,
}; NUM_READY_QUEUES];

#[no_mangle]
pub static mut ksReadyQueuesL2Bitmap: [[usize; L2_BITMAP_SIZE]; CONFIG_NUM_DOMAINS] =
    [[0; L2_BITMAP_SIZE]; CONFIG_NUM_DOMAINS];

#[no_mangle]
pub static mut ksReadyQueuesL1Bitmap: [usize; CONFIG_NUM_DOMAINS] = [0; CONFIG_NUM_DOMAINS];

#[no_mangle]
#[link_section = "._idle_thread"]
pub static mut ksIdleThreadTCB: [[u8; BIT!(seL4_TCBBits)]; CONFIG_MAX_NUM_NODES] =
    [[0; BIT!(seL4_TCBBits)]; CONFIG_MAX_NUM_NODES];
    