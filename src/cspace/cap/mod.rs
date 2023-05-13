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

use untyped::UntypedCap;
use cnode::CNodeCap;

use self::{null::NullCap, endpoint::EndpointCap, notification::NotificationCap, reply::ReplyCap, 
    thread::ThreadCap, irq_control::IRQControlCap, irq_handler::IRQHandlerCap, zombie::ZombieCap, 
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
    pub null_cap: NullCap,
    pub untyped_cap: UntypedCap,
    pub endpoint_cap: EndpointCap,
    pub notification_cap: NotificationCap,
    pub reply_cap: ReplyCap,
    pub cnode_cap: CNodeCap,
    pub thread_cap: ThreadCap,
    pub irq_control_cap: IRQControlCap,
    pub irq_handler_cap: IRQHandlerCap,
    pub zombie_cap: ZombieCap,
    pub domain_cap: DomainCap,
    pub frame_cap: FrameCap,
    pub page_table_cap: PageTableCap,
    pub asid_control_cap: ASIDControlCap,
    pub asid_pool_cap: ASIDPoolCap,
    pub unknown_cap: Cap,
}

impl cap_t {
    pub fn get_cap_type(&self) -> CapTag {
        unsafe {
            self.unknown_cap.get_cap_type()
        }
    }

}