use sel4_common::structures::exception_t;
use sel4_cspace::interface::cte_t;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Structure for the return value of lookupSlot_raw
pub struct lookupSlot_raw_ret_t {
    /// The status of the operation
    pub status: exception_t,
    /// The slot that was looked up
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
/// Structure for the return value of lookupSlot
pub struct lookupSlot_ret_t {
    /// The status of the operation
    pub status: exception_t,
    /// The slot that was looked up
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
