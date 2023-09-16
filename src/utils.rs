use common::{sel4_config::seL4_MinUntypedBits, BIT, structures::seL4_IPCBuffer};

pub fn MAX_FREE_INDEX(bits: usize) -> usize {
    BIT!(bits - seL4_MinUntypedBits)
}

#[inline]
pub fn ipc_buf_ref_to_usize_ptr(op_buf: Option<&seL4_IPCBuffer>) -> *mut usize {
    match op_buf {
        Some(buf) => {
            buf as *const seL4_IPCBuffer as *mut usize
        }
        _ => 0 as *mut usize
    }
}

#[inline]
pub fn clear_memory(ptr: *mut u8, bits: usize) {
    unsafe {
        core::slice::from_raw_parts_mut(ptr, BIT!(bits)).fill(0);
    }
}