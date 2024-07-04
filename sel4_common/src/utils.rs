//! Utility functions and macros.
use crate::sel4_config::*;
#[macro_export]
/// Define a bitfield struct with the given name, total words, type index, type offset, type bits, and a list of variants.
macro_rules! plus_define_bitfield {
    ($name:ident, $total_words:expr, $type_index:expr, $type_offset:expr, $type_bits:expr =>
        { $($variant:ident, $type_value:expr => { $($field:ident, $get_field:ident, $set_field:ident, $index:expr, $offset:expr, $bits:expr, $shift:expr, $sign_ext: expr),* }),* }) => {
        #[repr(C)]
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
/// Return fill the given number of bits with 1.
macro_rules! MASK {
    ($e:expr) => {
        {
             (1usize << $e) - 1usize
        }
    }
}

#[macro_export]
/// Calculate the floor of the given number.
macro_rules! ROUND_DOWN {
    ($n:expr,$b:expr) => {{
        ((($n) >> ($b)) << ($b))
    }};
}

#[macro_export]
/// Calculate the ceil of the given number.
macro_rules! ROUND_UP {
    ($n:expr,$b:expr) => {{
        ((((($n) - 1usize) >> ($b)) + 1usize) << ($b))
    }};
}

#[macro_export]
/// Judge whether the given number is aligned to the given number of bits.
macro_rules! IS_ALIGNED {
    ($n:expr,$b:expr) => {{
        $n & MASK!($b) == 0
    }};
}

#[macro_export]
/// Calculate 1 << n for given n.
macro_rules! BIT {
    ($e:expr) => {
        {
            1usize<<$e
        }
    }
}

#[inline]
pub fn MAX_FREE_INDEX(bits: usize) -> usize {
    BIT!(bits - seL4_MinUntypedBits)
}

#[inline]
pub fn convert_to_type_ref<T>(addr: usize) -> &'static T {
    assert_ne!(addr, 0);
    unsafe { &*(addr as *mut T) }
}

#[inline]
pub fn convert_to_mut_type_ref<T>(addr: usize) -> &'static mut T {
    assert_ne!(addr, 0);
    unsafe { &mut *(addr as *mut T) }
}

#[inline]
pub fn convert_to_mut_type_ref_unsafe<T>(addr: usize) -> &'static mut T {
    unsafe { &mut *(addr as *mut T) }
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

#[inline]
pub fn cpu_id() -> usize {
    #[cfg(feature = "ENABLE_SMP")]
    {
        use crate::smp::get_currenct_cpu_index;
        get_currenct_cpu_index()
    }
    #[cfg(not(feature = "ENABLE_SMP"))]
    {
        0
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
