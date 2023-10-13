use common::structures::exception_t;

use crate::cte::cte_t;


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct resolveAddressBits_ret_t {
    pub status: exception_t,
    pub slot: *mut cte_t,
    pub bitsRemaining: usize,
}

impl Default for resolveAddressBits_ret_t {
    #[inline]
    fn default() -> Self {
        resolveAddressBits_ret_t {
            status: exception_t::EXCEPTION_NONE,
            slot: 0 as *mut cte_t,
            bitsRemaining: 0,
        }
    }
}
