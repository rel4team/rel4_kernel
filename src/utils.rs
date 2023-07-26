use common::sel4_config::seL4_MinUntypedBits;


#[macro_export]
macro_rules! BIT {
    ($e:expr) => {
        {
            1usize<<$e
        }
    }
}

#[macro_export]
macro_rules! MASK {
    ($e:expr) => {
        {
             (1usize << $e) - 1usize
        }
    }
}

#[macro_export]
macro_rules! ROUND_DOWN {
    ($n:expr,$b:expr) => {{
        ((($n) >> ($b)) << ($b))
    }};
}

#[macro_export]
macro_rules! ROUND_UP {
    ($n:expr,$b:expr) => {{
        ((((($n) - 1usize) >> ($b)) + 1usize) << ($b))
    }};
}

#[macro_export]
macro_rules! IS_ALIGNED {
    ($n:expr,$b:expr) => {{
        $n & MASK!($b) == 0
    }};
}

pub fn ARRAY_SIZE<T>(arr: &[T]) -> usize {
    arr.len()
}

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