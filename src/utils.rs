use common::{sel4_config::seL4_MinUntypedBits, BIT, structures::seL4_IPCBuffer};


#[inline]
pub fn clear_memory(ptr: *mut u8, bits: usize) {
    unsafe {
        core::slice::from_raw_parts_mut(ptr, BIT!(bits)).fill(0);
    }
}