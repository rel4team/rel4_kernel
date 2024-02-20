mod config;
mod operations;

use bit_field::BitField;
use lazy_static::lazy_static;
use log::debug;
use spin::Mutex;
use crate::common::utils::{convert_to_mut_type_ref, convert_to_option_mut_type_ref, convert_to_type_ref, cpu_id};
use crate::task_manager::{get_currenct_thread, tcb_t};
use crate::task_manager::ipc::notification_t;
use crate::uintc::config::{UINTC_BASE, UINTC_ENTRY_NUM};
use crate::uintc::operations::{uintc_read_high, uintc_read_low, uintc_write_high, uintc_write_low};
use crate::uintr;
use crate::cspace::interface::{cap_t, CapTag};
use crate::uintr::sip;
use crate::vspace::{kpptr_to_paddr, pptr_to_paddr};

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
    pub static ref UINTR_RECV_ALLOCATOR: Mutex<IndexAllocator<UINTC_ENTRY_NUM>> = Mutex::new(IndexAllocator::<UINTC_ENTRY_NUM>::new());
    pub static ref UINTR_ST_POOL_ALLOCATOR: Mutex<IndexAllocator<16>> = Mutex::new(IndexAllocator::<16>::new());
    pub static ref UINTR_ST_ENTRY_ALLOCATOR: Mutex<[IndexAllocator<UINTC_ENTRY_NUM>; 16]> = Mutex::new([IndexAllocator::<UINTC_ENTRY_NUM>::new(); 16]);
}

#[no_mangle]
#[link_section = ".boot.uintr"]
static mut UINTR_ST_POOL: [u8; core::mem::size_of::<UIntrSTEntry>() * UINTC_ENTRY_NUM * 16] = [0; core::mem::size_of::<UIntrSTEntry>() * UINTC_ENTRY_NUM * 16];

#[derive(Debug)]
pub struct UIntrSTEntry(u64);
const DEFAULT_UIST_SIZE: usize = 1;

const UISTE_VEC_MASK: u64 = 0xffff << 16;

const UISTE_INDEX_MASK: u64 = 0xffff << 48;
impl UIntrSTEntry {
    /// Returns if this entry is valid.
    pub fn is_valid(&self) -> bool {
        (self.0 >> 63) != 0
    }

    /// Enables or disables this entry.
    pub fn set_valid(&mut self, valid: bool) {
        self.0.set_bit(0, valid);
    }

    /// Sets sender vector of this entry.
    pub fn set_vec(&mut self, vec: usize) {
        self.0 &= !UISTE_VEC_MASK;
        self.0 |= ((vec as u64) << 16) & UISTE_VEC_MASK;
    }

    /// Gets sender vector of this entry.
    pub fn get_vec(&self) -> usize {
        ((self.0 & UISTE_VEC_MASK) >> 16) as usize
    }

    /// Sets receiver index of this entry.
    pub fn set_index(&mut self, index: usize) {
        self.0 &= !UISTE_INDEX_MASK;
        self.0 |= ((index as u64) << 48) & UISTE_INDEX_MASK;
    }

    /// Gets receiver index of this entry.
    pub fn get_index(&self) -> usize {
        ((self.0 & UISTE_INDEX_MASK) >> 48) as usize
    }
}

/// User interrupt receiver status in UINTC
#[repr(C)]
#[derive(Debug)]
pub struct UIntrReceiver {
    /// Kernel defined architecture mode and valid bit.
    mode: u16,

    /// The integer ID of the hardware thread running the code.
    hartid: u16,

    /// Reserved bits.
    _reserved: u32,

    /// One bit for each user interrupt vector. There is user-interrupt request for a vector if the corresponding bit is 1.
    irq: u64,
}

impl UIntrReceiver {
    /// Gets a [`UIntrReceiver`] from UINTC by index.
    pub fn from(index: usize) -> Self {
        assert!(index < UINTC_ENTRY_NUM);
        let low = uintc_read_low(index);
        let high = uintc_read_high(index);
        Self {
            mode: low as u16,
            hartid: (low >> 16) as u16,
            _reserved: 0,
            irq: high,
        }
    }

    /// Synchronize UINTC with this [`UIntrReceiver`].
    pub fn sync(&self, index: usize) {
        let low = (self.mode as u64) | ((self.hartid as u64) << 16);
        let high = self.irq;
        uintc_write_low(index, low);
        uintc_write_high(index, high);
    }
}

pub fn register_receiver(ntfn: &mut notification_t, tcb: &mut tcb_t) {
    if tcb.tcbBoundNotification != ntfn.get_ptr() {
        debug!("fail to register uint receiver, need to bind ntfn first");
        return;
    }
    if let Some(recv_index) = UINTR_RECV_ALLOCATOR.lock().allocate() {
        debug!("recv index: {}", recv_index);
        ntfn.set_uintr_flag(1);
        ntfn.set_recv_idx(recv_index);
        let mut uirs = UIntrReceiver::from(recv_index);
        uirs.irq = 0;
        uirs.sync(recv_index);
        tcb.uintr_inner.utvec = uintr::utvec::read().bits();
        tcb.uintr_inner.uscratch = uintr::uscratch::read();
    } else {
        debug!("register_receiver fail");
    }
}

pub fn register_sender(ntfn_cap: &cap_t) {
    assert_eq!(ntfn_cap.get_cap_type(), CapTag::CapNotificationCap);
    let current = get_currenct_thread();
    if current.uintr_inner.uist.is_none() {
        if let Some(uist_idx) = UINTR_ST_POOL_ALLOCATOR.lock().allocate() {
            current.uintr_inner.uist = Some(uist_idx);
        } else {
            debug!("alloc sender table fail");
            return;
        }
    }
    let uist_idx = current.uintr_inner.uist.unwrap();
    let uiste_idx = UINTR_ST_ENTRY_ALLOCATOR.lock().get_mut(uist_idx).unwrap().allocate();
    if uiste_idx.is_none() {
        debug!("fail to alloc uiste. {}", uist_idx);
        return;
    }
    let offset = uiste_idx.unwrap();
    let entry = unsafe {
        debug!("UINTR_ST_POOL.as_ptr(): {:#x}", UINTR_ST_POOL.as_ptr() as usize);
        convert_to_mut_type_ref::<UIntrSTEntry>(UINTR_ST_POOL.as_ptr().offset(((uist_idx * UINTC_ENTRY_NUM + offset) * core::mem::size_of::<UIntrSTEntry>()) as isize) as usize)
    };
    entry.set_vec(offset);
    debug!("[register sender] recv_idx: {}", convert_to_type_ref::<notification_t>(ntfn_cap.get_nf_ptr()).get_recv_idx());
    entry.set_index(convert_to_type_ref::<notification_t>(ntfn_cap.get_nf_ptr()).get_recv_idx());
    entry.set_valid(true);
    // entry.set_reserved0(0);
    // entry.set_reserved1(0);
    debug!("entry: {:?}", entry);
    // debug!("{} {} {} {} {}", entry.get_send_vec(), entry.get_uirs_index(), entry.get_valid(), entry.get_reserved0(), entry.get_reserved1());
    let ipc_buffer = current.lookup_mut_ipc_buffer(true).unwrap();
    ipc_buffer.uintrFlag = offset;
    debug!("[register_sender] offset: {}", offset);
}

pub fn init() {
    uintr::suicfg::write(pptr_to_paddr(UINTC_BASE));
}

#[inline]
pub fn uintr_save() {
    get_currenct_thread().uintr_inner.uepc = uintr::uepc::read();
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
    let current = get_currenct_thread();
    if let Some(ntfn) = convert_to_option_mut_type_ref::<notification_t>(current.tcbBoundNotification) {
        if ntfn.get_uintr_flag() == 1 {
            let index = ntfn.get_recv_idx();
            let mut uirs = UIntrReceiver::from(index);
            uirs.hartid = {
                #[cfg(feature = "ENABLE_SMP")] {
                    crate::smp::cpu_index_to_id(cpu_id())
                }
                #[cfg(not(feature = "ENABLE_SMP"))]
                0
            } as u16;
            uirs.mode |= 0x2;
            uirs.sync(index);

            // user configurations
            uintr::uepc::write(current.uintr_inner.uepc);
            uintr::utvec::write(current.uintr_inner.utvec, uintr::utvec::TrapMode::Direct);
            uintr::uscratch::write(current.uintr_inner.uscratch);
            uintr::uie::set_usoft();

            // supervisor configurations
            uintr::suirs::write((1 << 63) | (index & 0xffff));
            uintr::sideleg::set_usoft();
            if uirs.irq != 0 {
                sip::set_usoft();
            } else {
                sip::clear_usoft();
            }
            return;
        }
    }
    uintr::suirs::write(0);
    uintr::sideleg::clear_usoft();
    sip::clear_usoft();
}

unsafe fn uist_init() {
    if let Some(uist_idx) = get_currenct_thread().uintr_inner.uist {
        let frame_addr = UINTR_ST_POOL.as_ptr().offset((uist_idx * core::mem::size_of::<UIntrSTEntry>() * UINTC_ENTRY_NUM) as isize) as usize;
        // debug!("frame_addr: {:#x}", frame_addr);
        uintr::suist::write((1 << 63) | (1 << 44) | (kpptr_to_paddr(frame_addr) >> 0xC));
    } else {
        uintr::suist::write(0);
    }
}
