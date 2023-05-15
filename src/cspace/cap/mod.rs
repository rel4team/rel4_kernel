mod untyped;
mod cnode;
mod asid_control;
mod asid_pool;
mod domain;
mod irq_control;
mod irq_handler;
mod notification;
mod null;
mod page_table;
mod reply;
mod thread;
mod zombie;
mod frame;
mod endpoint;

use cnode::CNodeCap;

use crate::{MASK, object::objecttype::{seL4_EndpointBits, seL4_NotificationBits, PT_SIZE_BITS, seL4_ReplyBits}, config::seL4_SlotBits, kernel::vspace::pageBitsForSize};

pub use self::{null::NullCap, endpoint::EndpointCap, notification::NotificationCap, reply::ReplyCap, 
    thread::ThreadCap, irq_control::IRQControlCap, irq_handler::IRQHandlerCap, zombie::ZombieCap, untyped::UntypedCap,
    domain::DomainCap, frame::FrameCap, page_table::PageTableCap, asid_control::ASIDControlCap, asid_pool::ASIDPoolCap};

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

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap {
    pub words: [usize; 2],
}

impl Default for Cap {
    fn default() -> Self {
        Cap { words: [0; 2] }
    }
}

impl Cap {
    fn get_cap_type(&self) -> CapTag {
        unsafe {
            core::mem::transmute::<u8, CapTag>(((self.words[0] >> 59) & 0x1f) as u8)
        }
    }
}

#[derive(Copy, Clone)]
pub union cap_t {
    null_cap: NullCap,
    untyped_cap: UntypedCap,
    endpoint_cap: EndpointCap,
    notification_cap: NotificationCap,
    reply_cap: ReplyCap,
    cnode_cap: CNodeCap,
    thread_cap: ThreadCap,
    irq_control_cap: IRQControlCap,
    irq_handler_cap: IRQHandlerCap,
    zombie_cap: ZombieCap,
    domain_cap: DomainCap,
    frame_cap: FrameCap,
    page_table_cap: PageTableCap,
    asid_control_cap: ASIDControlCap,
    asid_pool_cap: ASIDPoolCap,
    unknown_cap: Cap,
}

impl Default for cap_t {
    fn default() -> Self {
        cap_t { null_cap: NullCap::new() }
    }
}

impl cap_t {

    pub fn get_inner_mut_ref<T>(&mut self) -> &'static mut T {
        unsafe {
            &mut *(self as *mut Self as usize as *mut T)
        }
    }

    pub fn get_inner_ref<T>(&self) -> &'static T {
        unsafe {
            & *(self as *const Self as usize as *const T)
        }
    }

    pub fn to_struture_cap(&self) -> crate::structures::cap_t {
        crate::structures::cap_t {
            words: unsafe { self.unknown_cap.words }
        }
    }

    pub fn get_cap_type(&self) -> CapTag {
        self.get_inner_ref::<Cap>().get_cap_type()
    }

    pub fn get_cap_ptr(&self) -> usize {
        match self.get_cap_type() {
            CapTag::CapUntypedCap => self.get_inner_ref::<UntypedCap>().get_ptr(),
            CapTag::CapEndpointCap => self.get_inner_ref::<EndpointCap>().get_ptr(),
            CapTag::CapNotificationCap => self.get_inner_ref::<NotificationCap>().get_ptr(),
            CapTag::CapCNodeCap => self.get_inner_ref::<CNodeCap>().get_ptr(),
            CapTag::CapThreadCap => self.get_inner_ref::<ThreadCap>().get_tcb_ptr(),
            CapTag::CapZombieCap => {
                panic!("need to handle")
            },
            CapTag::CapFrameCap => self.get_inner_ref::<FrameCap>().get_base_ptr(),
            CapTag::CapPageTableCap => self.get_inner_ref::<PageTableCap>().get_base_ptr(),
            CapTag::CapASIDPoolCap => self.get_inner_ref::<ASIDPoolCap>().get_asid_pool(),
            _ => {
                panic!("invaild cap type");
            }
        }
    }

    pub fn get_cap_size_bits(&self) -> usize {
        match self.get_cap_type() {
            CapTag::CapUntypedCap => self.get_inner_ref::<UntypedCap>().get_block_size(),
            CapTag::CapEndpointCap => seL4_EndpointBits,
            CapTag::CapNotificationCap => seL4_NotificationBits,
            CapTag::CapCNodeCap => self.get_inner_ref::<CNodeCap>().get_radix() + seL4_SlotBits,
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

pub fn cap_null_cap_new() -> cap_t {
    cap_t {
        null_cap: NullCap::new()
    }
}

pub fn cap_untyped_cap_new(capFreeIndex: usize, capIsDevice: usize, capBlockSize: usize, capPtr: usize) -> cap_t {
    cap_t {
        untyped_cap: UntypedCap::new(capFreeIndex, capIsDevice, capBlockSize, capPtr)
    }
}

pub fn cap_endpoint_cap_new(capEPBadge: usize, capCanGrantReply: usize, capCanGrant: usize, capCanSend: usize, capCanReceive: usize, capEPPtr: usize) -> cap_t {
    cap_t {
        endpoint_cap: EndpointCap::new(capEPBadge, capCanGrantReply, capCanGrant, capCanSend, capCanReceive, capEPPtr),
    }
}

pub fn cap_zombie_cap_new(capZombieID: usize, capZombieType: usize) -> cap_t {
    cap_t {
        zombie_cap: ZombieCap::new(capZombieID, capZombieType)
    }
}

pub fn cap_page_table_cap_new(capPTMappedASID: usize, capPTBasePtr: usize, capPTIsMapped: usize, capPTMappedAddress: usize) -> cap_t {
    cap_t {
        page_table_cap: PageTableCap::new(capPTMappedASID, capPTBasePtr, capPTIsMapped, capPTMappedAddress)
    }
}

pub fn cap_frame_cap_new(capFMappedASID: usize, capFBasePtr: usize, capFSize: usize, capFVMRights: usize, capFIsDevice: usize, capFMappedAddress: usize) -> cap_t {
    cap_t {
        frame_cap: FrameCap::new(capFMappedASID, capFBasePtr, capFSize, capFVMRights, capFIsDevice, capFMappedAddress)
    }
}

pub fn cap_asid_control_cap_new() -> cap_t {
    cap_t {
        asid_control_cap: ASIDControlCap::new()
    }
}

pub fn cap_asid_pool_cap_new(capASIDBase: usize, capASIDPool: usize) -> cap_t {
    cap_t {
        asid_pool_cap: ASIDPoolCap::new(capASIDBase, capASIDPool)
    }
}

pub fn cap_domain_cap_new() -> cap_t {
    cap_t {
        domain_cap: DomainCap::new()
    }
}

pub fn cap_reply_cap_new(capReplyCanGrant: usize, capReplyMaster: usize, capTCBPtr: usize) -> cap_t {
    cap_t {
        reply_cap: ReplyCap::new(capReplyCanGrant, capReplyMaster, capTCBPtr)
    }
}

pub fn cap_thread_cap_new(capTCBPtr: usize) -> cap_t {
    cap_t {
        thread_cap: ThreadCap::new(capTCBPtr)
    }
}

pub fn cap_notification_cap_new(capNtfnBadge: usize, capNtfnCanReceive: usize, capNtfnCanSend: usize, capNtfnPtr: usize) -> cap_t {
    cap_t {
        notification_cap: NotificationCap::new(capNtfnBadge, capNtfnCanReceive, capNtfnCanSend, capNtfnPtr)
    }
}

pub fn cap_cnode_cap_new(capCNodeRadix: usize, capCNodeGuardSize: usize, capCNodeGuard: usize, capCNodePtr: usize) -> cap_t {
    cap_t {
        cnode_cap: CNodeCap::new(capCNodeRadix, capCNodeGuardSize, capCNodeGuard, capCNodePtr)
    }
}

pub fn cap_irq_control_cap_new() -> cap_t {
    cap_t {
        irq_control_cap: IRQControlCap::new()
    }
}

pub fn cap_irq_handler_cap_new(capIRQ: usize) -> cap_t {
    cap_t {
        irq_handler_cap: IRQHandlerCap::new(capIRQ)
    }
}

pub fn same_region_as(cap1: &cap_t, cap2: &cap_t) -> bool {
    match cap1.get_cap_type() {
        CapTag::CapUntypedCap => {
            if cap2.get_cap_is_physical() {
                let aBase = cap1.get_inner_ref::<UntypedCap>().get_ptr();
                let bBase = cap2.get_cap_ptr();

                let aTop = aBase + MASK!(cap1.get_inner_ref::<UntypedCap>().get_block_size());
                let bTop = bBase + MASK!(cap2.get_cap_size_bits());
                return (aBase <= bBase) && (bTop <= aTop) && (bBase <= bTop);
            }

            return false;
        }
        CapTag::CapFrameCap => {
            if cap2.get_cap_type() == CapTag::CapFrameCap {
                let botA = cap1.get_inner_ref::<FrameCap>().get_base_ptr();
                let botB = cap2.get_inner_ref::<FrameCap>().get_base_ptr();
                let topA = botA + MASK!(pageBitsForSize(cap1.get_inner_ref::<FrameCap>().get_size()));
                let topB = botB + MASK!(pageBitsForSize(cap2.get_inner_ref::<FrameCap>().get_size()));
                return (botA <= botB) && (topA >= topB) && (botB <= topB);
            }
            false 
        }
        CapTag::CapEndpointCap => {
            if cap2.get_cap_type() == CapTag::CapEndpointCap {
                return cap1.get_inner_ref::<EndpointCap>().get_ptr() == cap2.get_inner_ref::<EndpointCap>().get_ptr();
            }
            false
        }
        CapTag::CapNotificationCap => {
            if cap2.get_cap_type() == CapTag::CapNotificationCap {
                return cap1.get_inner_ref::<NotificationCap>().get_ptr()
                    == cap2.get_inner_ref::<NotificationCap>().get_ptr();
            }
            false
        }
        CapTag::CapPageTableCap => {
            if cap2.get_cap_type() == CapTag::CapPageTableCap {
                return cap1.get_inner_ref::<PageTableCap>().get_base_ptr()
                    == cap2.get_inner_ref::<PageTableCap>().get_base_ptr();
            }
            false
        }
        CapTag::CapASIDControlCap => {
            if cap2.get_cap_type() == CapTag::CapASIDControlCap {
                return true;
            }
            false
        }
        CapTag::CapASIDPoolCap => {
            if cap2.get_cap_type() == CapTag::CapASIDPoolCap {
                return cap1.get_inner_ref::<ASIDPoolCap>().get_asid_pool()
                    == cap2.get_inner_ref::<ASIDPoolCap>().get_asid_pool();
            }
            false
        }
        CapTag::CapCNodeCap => {
            if cap2.get_cap_type() == CapTag::CapCNodeCap {
                return (cap1.get_inner_ref::<CNodeCap>().get_ptr()
                    == cap2.get_inner_ref::<CNodeCap>().get_ptr())
                    && (cap1.get_inner_ref::<CNodeCap>().get_radix()
                        == cap2.get_inner_ref::<CNodeCap>().get_radix());
            }
            false
        }
        CapTag::CapThreadCap => {
            if cap2.get_cap_type() == CapTag::CapThreadCap {
                return cap1.get_inner_ref::<ThreadCap>().get_tcb_ptr() == cap2.get_inner_ref::<ThreadCap>().get_tcb_ptr();
            }
            false
        }
        CapTag::CapDomainCap => {
            if cap2.get_cap_type() == CapTag::CapDomainCap {
                return true;
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
                return cap1.get_inner_ref::<IRQHandlerCap>().get_irq()
                    == cap2.get_inner_ref::<IRQHandlerCap>().get_irq();
            }
            false
        }
        _ => {
            return false;
        }
    }
}



pub fn is_cap_revocable(derived_cap: &cap_t, src_cap: &cap_t) -> bool {
    if derived_cap.isArchCap() {
        return false;
    }

    match derived_cap.get_cap_type() {
        CapTag::CapEndpointCap => {
            assert_eq!(src_cap.get_cap_type(), CapTag::CapEndpointCap);
            return derived_cap.get_inner_ref::<EndpointCap>().get_badge() != src_cap.get_inner_ref::<EndpointCap>().get_badge();
        }

        CapTag::CapNotificationCap => {
            assert_eq!(src_cap.get_cap_type(), CapTag::CapNotificationCap);
            return derived_cap.get_inner_ref::<NotificationCap>().get_badge() != src_cap.get_inner_ref::<NotificationCap>().get_badge();
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