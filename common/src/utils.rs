use crate::sel4_config::{RISCVPageBits, RISCVMegaPageBits, RISCVGigaPageBits, RISCV_4K_Page, RISCV_Mega_Page, RISCV_Giga_Page};

#[macro_export]
macro_rules! plus_define_bitfield {
    ($name:ident, $total_words:expr, $type_index:expr, $type_offset:expr, $type_bits:expr =>
        { $($variant:ident, $type_value:expr => { $($field:ident, $get_field:ident, $set_field:ident, $index:expr, $offset:expr, $bits:expr, $shift:expr, $sign_ext: expr),* }),* }) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            pub words: [usize; $total_words],
        }
        
        impl $name {
            $(
                #[inline]
                pub fn $variant($($field: usize),*) -> Self {
                    let mut value = $name::default();
                    $(
                        let mask = (((1u128 << $bits) - 1)) as usize;
                        value.words[$index] |= ((($field >> $shift) & mask) << $offset);
                    )*
                    value.words[$type_index] |= (($type_value & ((1usize << $type_bits) - 1)) << $type_offset);

                    value
                }

                $(
                    #[inline]
                    pub fn $get_field(&self) -> usize {
                        let mask = ((1u128 << $bits) - 1) as usize;
                        let mut ret = ((self.words[$index] >> $offset) & mask) << $shift;
                        if $sign_ext && (ret & (1usize << 38)) != 0 {
                            ret |= 0xffffff8000000000;
                        }
                        ret
                    }

                    #[inline]
                    pub fn $set_field(&mut self, new_field: usize) {
                        let mask = ((1u128 << $bits) - 1) as usize;
                        self.words[$index] &= !(mask << $offset);
                        self.words[$index] |= (((new_field >> $shift) & mask) << $offset);
                    }
                )*
            )*
            
            #[inline]
            pub fn get_type(&self) -> usize {
                (self.words[$type_index] >> $type_offset) & ((1usize << $type_bits) - 1)
            }
        }
    };
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

#[inline]
pub fn convert_to_option_type_ref<T>(addr: usize) -> Option<&'static T> {
    if addr == 0 {
        return None;
    }
    Some(convert_to_type_ref::<T>(addr))
}

#[inline]
pub fn convert_to_option_mut_type_ref<T>(addr: usize) -> Option<&'static mut T> {
    if addr == 0 {
        return None;
    }
    Some(convert_to_mut_type_ref::<T>(addr))
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