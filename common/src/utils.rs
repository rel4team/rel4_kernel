use crate::sel4_config::{RISCVPageBits, RISCVMegaPageBits, RISCVGigaPageBits, RISCV_4K_Page, RISCV_Mega_Page, RISCV_Giga_Page};

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

#[macro_export]
macro_rules! BIT {
    ($e:expr) => {
        {
            1usize<<$e
        }
    }
}


#[inline]
pub fn convert_to_type_ref<T>(addr: usize) -> &'static T {
    assert_ne!(addr, 0);
    unsafe {
        & *(addr as *mut T)
    }
}

#[inline]
pub fn convert_to_mut_type_ref<T>(addr: usize) -> &'static mut T {
    assert_ne!(addr, 0);
    unsafe {
        &mut *(addr as *mut T)
    }
}
#[no_mangle]
#[inline]
pub fn pageBitsForSize(page_size: usize) -> usize {
    match page_size {
        RISCV_4K_Page => RISCVPageBits,
        RISCV_Mega_Page => RISCVMegaPageBits,
        RISCV_Giga_Page => RISCVGigaPageBits,
        _ => panic!("Invalid page size!"),
    }
}


#[inline]
pub fn hart_id() -> usize {
    0
}

pub struct ListQueue {
    pub head: usize,
    pub tail: usize,
}