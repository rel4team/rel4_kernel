use common::{sel4_config::seL4_MinUntypedBits, BIT};

pub fn MAX_FREE_INDEX(bits: usize) -> usize {
    BIT!(bits - seL4_MinUntypedBits)
}

#[inline]
pub fn convert_to_mut_type_ref<T>(addr: usize) -> &'static mut T {
    assert_ne!(addr, 0);
    unsafe {
        &mut *(addr as *mut T)
    }
}

#[inline]
pub fn convert_to_type_ref<T>(addr: usize) -> &'static T {
    assert_ne!(addr, 0);
    unsafe {
        & *(addr as *mut T)
    }
}