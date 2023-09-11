use common::{sel4_config::{seL4_EndpointBits, seL4_NotificationBits, seL4_SlotBits, PT_SIZE_BITS, seL4_ReplyBits, wordBits}, MASK, utils::pageBitsForSize};

pub mod asid_control;
pub mod asid_pool;
pub mod cnode;
pub mod domain;
pub mod endpoint;
pub mod frame;
pub mod irq_control;
pub mod irq_handler;
pub mod notification;
pub mod null;
pub mod page_table;
pub mod reply;
pub mod thread;
pub mod untyped;
pub mod zombie;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct CNodeCapData {
    pub words: [usize; 1],
}

impl CNodeCapData {
    #[inline]
    pub fn new(data: usize) -> Self {
        CNodeCapData { words: [data] }
    }

    #[inline]
    pub fn get_guard(&self) -> usize {
        (self.words[0] & 0xffffffffffffffc0usize) >> 6
    }

    #[inline]
    pub fn get_guard_size(&self) -> usize {
        self.words[0] & 0x3fusize
    }
}

/// Cap 在内核态中的种类枚举
#[derive(Eq, PartialEq, Debug)]
pub enum CapTag {
    CapNullCap = 0,
    CapUntypedCap = 2,
    CapEndpointCap = 4,
    CapNotificationCap = 6,
    CapReplyCap = 8,
    CapCNodeCap = 10,
    CapThreadCap = 12,
    CapIrqControlCap = 14,
    CapIrqHandlerCap = 16,
    CapZombieCap = 18,
    CapDomainCap = 20,
    CapFrameCap = 1,
    CapPageTableCap = 3,
    CapASIDControlCap = 11,
    CapASIDPoolCap = 13
}


/// cap_t 表示一个capability，由两个机器字组成，包含了类型、对象元数据以及指向内核对象的指针。
/// 每个类型的capability的每个字段都实现了get和set方法。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct cap_t {
    pub words: [usize; 2],
}

impl Default for cap_t {
    fn default() -> Self {
        cap_t { words: [0; 2] }
    }
}


/// cap 的公用方法
impl cap_t {
    pub fn update_data(&self, preserve: bool, new_data: usize) -> Self {
        if self.isArchCap() {
            return self.clone();
        }
        match self.get_cap_type() {
            CapTag::CapEndpointCap => {
                if !preserve && self.get_ep_badge() == 0 {
                    let mut new_cap = self.clone();
                    new_cap.set_ep_badge(new_data);
                    new_cap
                } else {
                    cap_t::new_null_cap()
                }
            }

            CapTag::CapNotificationCap => {
                if !preserve && self.get_nf_badge() == 0 {
                    let mut new_cap = self.clone();
                    new_cap.set_nf_badge(new_data);
                    new_cap
                } else {
                    cap_t::new_null_cap()
                }
            }

            CapTag::CapCNodeCap => {
                let w = CNodeCapData::new(new_data);
                let guard_size = w.get_guard_size();
                if guard_size + self.get_cnode_radix() > wordBits {
                    return cap_t::new_null_cap();
                }
                let guard = w.get_guard() & MASK!(guard_size);
                let mut new_cap = self.clone();
                new_cap.set_cnode_guard(guard);
                new_cap.set_cnode_guard_size(guard_size);
                new_cap
            }
            _ => { self.clone() }
        }
    }

    pub fn get_cap_type(&self) -> CapTag {
        unsafe {
            core::mem::transmute::<u8, CapTag>(((self.words[0] >> 59) & 0x1f) as u8)
        }
    }

    pub fn get_cap_ptr(&self) -> usize {
        match self.get_cap_type() {
            CapTag::CapUntypedCap => self.get_untyped_ptr(),
            CapTag::CapEndpointCap => self.get_ep_ptr(),
            CapTag::CapNotificationCap => self.get_nf_ptr(),
            CapTag::CapCNodeCap => self.get_cnode_ptr(),
            CapTag::CapThreadCap => self.get_tcb_ptr(),
            CapTag::CapZombieCap => self.get_zombie_ptr(),
            CapTag::CapFrameCap => self.get_frame_base_ptr(),
            CapTag::CapPageTableCap => self.get_pt_base_ptr(),
            CapTag::CapASIDPoolCap => self.get_asid_pool(),
            _ => {
                0
            }
        }
    }

    pub fn get_cap_size_bits(&self) -> usize {
        match self.get_cap_type() {
            CapTag::CapUntypedCap => self.get_untyped_block_size(),
            CapTag::CapEndpointCap => seL4_EndpointBits,
            CapTag::CapNotificationCap => seL4_NotificationBits,
            CapTag::CapCNodeCap => self.get_cnode_radix() + seL4_SlotBits,
            CapTag::CapPageTableCap => PT_SIZE_BITS,
            CapTag::CapReplyCap => seL4_ReplyBits,
            _ => 0,
        }
    }

    pub fn get_cap_is_physical(&self) -> bool {
        match self.get_cap_type() {
            CapTag::CapUntypedCap | CapTag::CapEndpointCap | CapTag::CapNotificationCap | CapTag::CapCNodeCap | CapTag::CapFrameCap | CapTag::CapASIDPoolCap |
            CapTag::CapPageTableCap | CapTag::CapZombieCap | CapTag::CapThreadCap => true,
            _ => false,
        }
    }

    pub fn isArchCap(&self) -> bool {
        self.get_cap_type() as usize % 2 != 0
    }
}

pub fn same_region_as(cap1: &cap_t, cap2: &cap_t) -> bool {
    match cap1.get_cap_type() {
        CapTag::CapUntypedCap => {
            if cap2.get_cap_is_physical() {
                let aBase = cap1.get_untyped_ptr();
                let bBase = cap2.get_cap_ptr();

                let aTop = aBase + MASK!(cap1.get_untyped_block_size());
                let bTop = bBase + MASK!(cap2.get_cap_size_bits());
                return (aBase <= bBase) && (bTop <= aTop) && (bBase <= bTop);
            }

            return false;
        }
        CapTag::CapFrameCap => {
            if cap2.get_cap_type() == CapTag::CapFrameCap {
                let botA = cap1.get_frame_base_ptr();
                let botB = cap2.get_frame_base_ptr();
                let topA = botA + MASK!(pageBitsForSize(cap1.get_frame_size()));
                let topB = botB + MASK!(pageBitsForSize(cap2.get_frame_size()));
                return (botA <= botB) && (topA >= topB) && (botB <= topB);
            }
            false 
        }
        CapTag::CapEndpointCap | CapTag::CapNotificationCap | CapTag::CapPageTableCap | CapTag::CapASIDPoolCap 
            | CapTag::CapThreadCap => {
            if cap2.get_cap_type() == cap1.get_cap_type() {
                return cap1.get_cap_ptr() == cap2.get_cap_ptr();
            }
            false
        }
        CapTag::CapASIDControlCap | CapTag::CapDomainCap => {
            if cap2.get_cap_type() == cap1.get_cap_type() {
                return true;
            }
            false
        }
        CapTag::CapCNodeCap => {
            if cap2.get_cap_type() == CapTag::CapCNodeCap {
                return (cap1.get_cnode_ptr() == cap2.get_cnode_ptr())
                    && (cap1.get_cnode_radix() == cap2.get_cnode_radix());
            }
            false
        }
        CapTag::CapIrqControlCap => {
            match cap2.get_cap_type() {
                CapTag::CapIrqControlCap | CapTag::CapIrqHandlerCap => {
                    true
                }
                _ => false
            }
        }
        CapTag::CapIrqHandlerCap => {
            if cap2.get_cap_type() == CapTag::CapIrqHandlerCap {
                return cap1.get_irq_handler() == cap2.get_irq_handler();
            }
            false
        }
        _ => {
            return false;
        }
    }
}

/// 判断两个cap指向的内核对象是否是同一个内存区域
pub fn same_object_as(cap1: &cap_t, cap2: &cap_t) -> bool {
    if cap1.get_cap_type() == CapTag::CapUntypedCap {
        return false;
    }
    if cap1.get_cap_type() == CapTag::CapIrqControlCap && cap2.get_cap_type() == CapTag::CapIrqHandlerCap {
        return false;
    }
    if cap1.isArchCap() && cap2.isArchCap() {
        return arch_same_object_as(cap1, cap2);
    }
    same_region_as(cap1, cap2)
}

fn arch_same_object_as(cap1: &cap_t, cap2: &cap_t) -> bool {
    if cap1.get_cap_type() == CapTag::CapFrameCap && cap2.get_cap_type() == CapTag::CapFrameCap {
        return cap1.get_frame_base_ptr() == cap2.get_frame_base_ptr()
            && cap1.get_frame_size() == cap2.get_frame_size()
            && (cap1.get_frame_is_device() == 0) == (cap2.get_frame_is_device() == 0)
    }
    same_region_as(cap1, cap2)
}

pub fn is_cap_revocable(derived_cap: &cap_t, src_cap: &cap_t) -> bool {
    if derived_cap.isArchCap() {
        return false;
    }

    match derived_cap.get_cap_type() {
        CapTag::CapEndpointCap => {
            assert_eq!(src_cap.get_cap_type(), CapTag::CapEndpointCap);
            return derived_cap.get_ep_badge() != src_cap.get_ep_badge();
        }

        CapTag::CapNotificationCap => {
            assert_eq!(src_cap.get_cap_type(), CapTag::CapNotificationCap);
            return derived_cap.get_nf_badge() != src_cap.get_nf_badge();
        }

        CapTag::CapIrqHandlerCap => {
            return src_cap.get_cap_type() == CapTag::CapIrqControlCap;
        }

        CapTag::CapUntypedCap => {
            return true;
        }
        
        _ => false
    }
}


pub fn updateCapData(preserve: bool, newData: usize, _cap: &cap_t) -> cap_t {
    _cap.update_data(preserve, newData)
}
