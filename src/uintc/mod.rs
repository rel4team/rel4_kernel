pub(crate) mod config;
mod operations;

use alloc::collections::BTreeMap;
use bit_field::BitField;
use lazy_static::lazy_static;
use log::debug;
use spin::Mutex;
use crate::common::utils::{convert_to_mut_type_ref, convert_to_option_mut_type_ref, convert_to_option_type_ref, convert_to_type_ref, cpu_id};
use crate::task_manager::{get_currenct_thread, tcb_t};
use crate::task_manager::ipc::notification_t;
use crate::uintc::config::{UINTC_BASE, UINTC_ENTRY_NUM};
use crate::uintc::operations::{uintc_read_high, uintc_read_low, uintc_write_high, uintc_write_low};
use crate::uintr;
use alloc::sync::Arc;
use crate::cspace::interface::{cap_t, CapTag};
use crate::uintr::{sip, suicfg, suirs, suist, uipi_read, uipi_send, uipi_write};
use crate::vspace::{kpptr_to_paddr, pptr_to_paddr};
use taic_driver::{LocalQueue, Taic};
use crate::smp::{cpu_index_to_id, get_currenct_cpu_index, hart_id_to_core_id};

#[derive(Copy, Clone)]
pub struct IndexAllocator<const SIZE: usize> where
    [(); (SIZE + 7) / 8]: {
    bitmap: [u8; (SIZE + 7) / 8]
}

impl<const SIZE: usize> IndexAllocator<SIZE> where
    [(); (SIZE + 7) / 8]: {
    pub fn new() -> Self {
        Self {
            bitmap :[0; (SIZE + 7) / 8]
        }
    }

    pub fn allocate(&mut self) -> Option<usize> {
        (0..SIZE).find(|i| {self.bitmap[i / 8] & (1 << (i % 8)) == 0 }).map(|index| {
            self.bitmap[index / 8] |= 1 << (index % 8);
            index
        })
    }

    pub fn release(&mut self, index: usize) {
        self.bitmap[index / 8] &= !(1 << (index % 8));
    }
}

lazy_static! {
    pub static ref UINTR_PROCESS_ALLOCATOR: Mutex<IndexAllocator<UINTC_ENTRY_NUM>> = Mutex::new(IndexAllocator::<UINTC_ENTRY_NUM>::new());
    // pub static ref UINTR_ST_POOL_ALLOCATOR: Mutex<IndexAllocator<16>> = Mutex::new(IndexAllocator::<16>::new());
    // pub static ref UINTR_ST_ENTRY_ALLOCATOR: Mutex<[IndexAllocator<UINTC_ENTRY_NUM>; 16]> = Mutex::new([IndexAllocator::<UINTC_ENTRY_NUM>::new(); 16]);
    pub static ref KERNEL_SENDER_POOL_IDX: usize = 0;
    // pub static ref NET_UINTR_IDX: Mutex<usize> = unsafe {
    //     let uist_idx = *KERNEL_SENDER_POOL_IDX.lock();
    //     let idx = UINTR_ST_ENTRY_ALLOCATOR.lock().get_mut(uist_idx).unwrap().allocate().unwrap();
    //     let entry = convert_to_mut_type_ref::<UIntrSTEntry>(UINTR_ST_POOL.as_ptr().offset(((
    //         uist_idx * UINTC_ENTRY_NUM + idx) * core::mem::size_of::<UIntrSTEntry>()) as isize) as usize);
    //     entry.set_valid(true);
    //     entry.set_vec(0);
    //     entry.set_index(0);
    //     Mutex::new(idx)
    // };
}

#[no_mangle]
// #[link_section = ".boot.uintr"]
// pub(crate) static mut UINTR_ST_POOL: [u8; core::mem::size_of::<UIntrSTEntry>() * UINTC_ENTRY_NUM * 16] = [0; core::mem::size_of::<UIntrSTEntry>() * UINTC_ENTRY_NUM * 16];

#[derive(Debug)]
pub struct UIntrSTEntry(u64);
const DEFAULT_UIST_SIZE: usize = 1;

const UISTE_VEC_MASK: u64 = 0xffff << 16;

const UISTE_INDEX_MASK: u64 = 0xffff << 48;


const TAIC_BASE: usize = axconfig::PHYS_VIRT_OFFSET + axconfig::MMIO_REGIONS[1].0;
const LQ_NUM: usize = 8;
const TAIC: Taic = Taic::new(TAIC_BASE, LQ_NUM);

static ALLOCATE_ID_TO_RS_ID: [usize; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

static mut LQ_MAP: BTreeMap<usize, Arc<LocalQueue>> = BTreeMap::new();

pub fn register_receiver(ntfn: &mut notification_t, tcb: &mut tcb_t) {
    if tcb.tcbBoundNotification != ntfn.get_ptr() {
        debug!("fail to register uint receiver, need to bind ntfn first");
        return;
    }
    if let Some(mut recv_index) = UINTR_PROCESS_ALLOCATOR.lock().allocate() {
        recv_index = ALLOCATE_ID_TO_RS_ID[recv_index];
        debug!("recv index: {}", recv_index);
        ntfn.set_uintr_flag(1);
        ntfn.set_recv_idx(recv_index);
        let lq = Arc::new(TAIC.alloc_lq(1, recv_index).unwrap());
        unsafe {
            LQ_MAP.insert(recv_index, lq);
        }
        tcb.uintr_inner.utvec = riscv::register::utvec::read().bits();
        let ipc_buffer = tcb.lookup_mut_ipc_buffer(true).unwrap();
        ipc_buffer.uintrFlag = recv_index;
    } else {
        debug!("register_receiver fail");
    }
}

pub fn register_sender(ntfn_cap: &cap_t) {
    assert_eq!(ntfn_cap.get_cap_type(), CapTag::CapNotificationCap);
    let current = get_currenct_thread();
    if current.uintr_inner.uist.is_none() {
        if let Some(uist_idx) = UINTR_PROCESS_ALLOCATOR.lock().allocate() {
            current.uintr_inner.uist = Some(uist_idx);
        } else {
            debug!("alloc sender table fail");
            return;
        }
    }
    let ipc_buffer = current.lookup_mut_ipc_buffer(true).unwrap();
    ipc_buffer.uintrFlag = current.uintr_inner.uist.unwrap();
    debug!("[register_sender] offset: {}", current.uintr_inner.uist.unwrap());
}

pub fn register_sender_async_syscall(ntfn_cap: &cap_t) -> isize {
    assert_eq!(ntfn_cap.get_cap_type(), CapTag::CapNotificationCap);
    let uist_idx = *KERNEL_SENDER_POOL_IDX;
    
    return uist_idx as isize;
}


pub fn init() {
    debug!("UINTC_BASE: {:#x}", UINTC_BASE);
    // uintr::suicfg::write(pptr_to_paddr(UINTC_BASE));
}

#[inline]
pub fn uintr_save() {
    let current = get_currenct_thread();
    current.uintr_inner.uepc = uintr::uepc::read();
    if let Some(ntfn) = convert_to_option_type_ref::<notification_t>(current.tcbBoundNotification) {
        let recv_idx = ntfn.get_recv_idx();
        unsafe {
            if let Some(lq) = LQ_MAP.get(&recv_idx) {
                lq.whart(cpu_index_to_id(get_currenct_cpu_index()));
            }
        }
    }
}

#[inline]
pub fn uintr_return() {
    unsafe {
        // for receiver
        uirs_restore();

        // for sender
        uist_init();
    }
}

unsafe fn uirs_restore() { 
    use riscv::register::{sideleg, uie, ustatus, utvec, uepc};
    let current = get_currenct_thread();
    sideleg::set_usoft();
    uepc::write(current.uintr_inner.uepc);
    utvec::write(current.uintr_inner.utvec, utvec::TrapMode::Direct);
    uie::set_usoft();
    ustatus::set_uie();
    if let Some(ntfn) = convert_to_option_type_ref::<notification_t>(current.tcbBoundNotification) {
        let recv_idx = ntfn.get_recv_idx();
        if let Some(lq) = LQ_MAP.get(&recv_idx) {
            lq.whart(cpu_index_to_id(get_currenct_cpu_index()));
        }
    }
}

unsafe fn uist_init() {

}