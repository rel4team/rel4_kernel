use crate::{structures::exception_t, println, kernel::boot::current_syscall_error, config::{seL4_IllegalOperation, seL4_RevokeFirst}, cspace::cap::{cap_null_cap_new, EndpointCap, NotificationCap}};

use super::{cap::{cap_t, CapTag, same_region_as, FrameCap, PageTableCap}, mdb::mdb_node_t};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct cte_t {
    pub cap: cap_t,
    pub cteMDBNode: mdb_node_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct deriveCap_ret {
    pub status: exception_t,
    pub cap: cap_t,
}


impl cte_t {
    pub fn derive_cap(&mut self, cap: &cap_t) -> deriveCap_ret {
        if cap.isArchCap() {
            return unsafe { self.arch_derive_cap(cap) }
        }
        let mut ret = deriveCap_ret {
            status: exception_t::EXCEPTION_NONE,
            cap: cap_t::default(),
        };

        match cap.get_cap_type() {
            CapTag::CapZombieCap => {
                ret.cap = cap_null_cap_new();
            }
            CapTag::CapUntypedCap => {
                ret.status = self.ensure_no_children();
                if ret.status != exception_t::EXCEPTION_NONE {
                    ret.cap = cap_null_cap_new();
                } else {
                    ret.cap = cap.clone();
                }
            }
            CapTag::CapReplyCap => {
                ret.cap = cap_null_cap_new();
            }
            CapTag::CapIrqControlCap => {
                ret.cap = cap_null_cap_new();
            }
            _ => {
                ret.cap = cap.clone();
            }
        }
        ret
    }

    unsafe fn arch_derive_cap(&mut self, cap: &cap_t) -> deriveCap_ret {
        let mut ret = deriveCap_ret {
            status: exception_t::EXCEPTION_NONE,
            cap: cap_t::default(),
        };
        match cap.get_cap_type() {
            CapTag::CapPageTableCap => {
                if cap.get_inner_ref::<PageTableCap>().get_is_mapped() != 0 {
                    ret.cap = cap.clone();
                    ret.status = exception_t::EXCEPTION_NONE;
                } else {
                    println!(" error:this page table cap is not mapped");
                    unsafe {
                        current_syscall_error._type = seL4_IllegalOperation;
                        ret.cap = cap_null_cap_new();
                        ret.status = exception_t::EXCEPTION_SYSCALL_ERROR;
                    }
                }
            }
            CapTag::CapFrameCap => {
                let mut newCap = cap.clone();
                newCap.get_inner_mut_ref::<FrameCap>().set_mapped_address(0);
                newCap.get_inner_mut_ref::<FrameCap>().set_mapped_asid(0);
                ret.cap = newCap;
            }
            CapTag::CapASIDControlCap | CapTag::CapASIDPoolCap => {
                ret.cap = cap.clone();
            }
            _ => {
                panic!(" Invalid arch cap type : {}", cap.get_cap_type() as usize);
            }
        }
        ret
    }

    fn ensure_no_children(&self) -> exception_t {
        if self.cteMDBNode.get_next() != 0 {
            unsafe {
                let next = & *(self.cteMDBNode.get_next() as *mut cte_t);
                if self.is_mdb_parent_of(next) {
                    current_syscall_error._type = seL4_RevokeFirst;
                    return exception_t::EXCEPTION_SYSCALL_ERROR;
                }
            }
        }
        return exception_t::EXCEPTION_NONE;
    }

    unsafe fn is_mdb_parent_of(&self, next: &Self) -> bool {
        if !(self.cteMDBNode.get_revocable() != 0) {
            return false;
        }
        if !same_region_as(&self.cap, &next.cap) {
            return false;
        }

        match self.cap.get_cap_type() {
            CapTag::CapEndpointCap => {
                assert_eq!(next.cap.get_cap_type(), CapTag::CapEndpointCap);
                let badge = self.cap.get_inner_ref::<EndpointCap>().get_badge();
                if badge == 0 {
                    return true;
                }
                return badge == next.cap.get_inner_ref::<EndpointCap>().get_badge() &&
                    !(next.cteMDBNode.get_first_badged() != 0);
            }
            CapTag::CapNotificationCap => {
                assert_eq!(next.cap.get_cap_type(), CapTag::CapNotificationCap);
                let badge = self.cap.get_inner_ref::<NotificationCap>().get_badge();
                if badge == 0 {
                    return true;
                }
                return badge == next.cap.get_inner_ref::<NotificationCap>().get_badge() &&
                    !(next.cteMDBNode.get_first_badged() != 0);
            }
            _ => true
        }
    }
}
