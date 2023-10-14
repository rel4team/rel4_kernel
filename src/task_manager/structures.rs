use crate::common::structures::exception_t;
use crate::cspace::interface::cte_t;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]

pub struct lookupSlot_raw_ret_t {
    pub status: exception_t,
    pub slot: *mut cte_t,
}

impl Default for lookupSlot_raw_ret_t {
    fn default() -> Self {
        lookupSlot_raw_ret_t {
            status: exception_t::EXCEPTION_NONE,
            slot: 0 as *mut cte_t,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct lookupSlot_ret_t {
    pub status: exception_t,
    pub slot: *mut cte_t,
}

impl Default for lookupSlot_ret_t {
    fn default() -> Self {
        lookupSlot_ret_t {
            status: exception_t::EXCEPTION_NONE,
            slot: 0 as *mut cte_t,
        }
    }
}