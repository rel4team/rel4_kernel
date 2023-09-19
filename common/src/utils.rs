use crate::sel4_config::{RISCVPageBits, RISCVMegaPageBits, RISCVGigaPageBits, RISCV_4K_Page, RISCV_Mega_Page, RISCV_Giga_Page};

#[macro_export]
macro_rules! define_bitfield {
    ($name:ident, $total_bits:ident, $type_offset:expr, $type_bits:expr =>
        { $($variant:ident, $type_value:expr => { $($field:ident, $get_field:ident, $set_field:ident, $offset:expr, $bits:expr, $addr:expr),* }),* }) => {
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub struct $name(pub $total_bits);

        impl $name {
            $(
                #[inline]
                pub fn $variant($($field: usize),*) -> Self {
                    let mut value: $total_bits = 0;
                    $(
                        let mask = (1 << $bits) - 1;
                        value |= (($field as $total_bits) & mask) << $offset;
                    )*
                    let mask = (1 << $type_bits) - 1;
                    value |= (($type_value as $total_bits) & mask) << $type_offset;

                    $name(value)
                }

                $(
                    #[inline]
                    pub fn $get_field(&self) -> usize {
                        let mask = (1 << $bits) - 1;
                        let mut value = ((self.0 >> $offset) & mask) as usize;
                        
                        if $addr {
                            value = (value << ($offset % 64)) as usize;
                            if (value & (1usize << ($bits + $offset - 1))) != 0 {
                                value |= (!((1usize << $bits + $offset) - 1));
                            }
                            value
                        } else {
                            value
                        }
                    }

                    #[inline]
                    pub fn $set_field(&mut self, new_field: usize) {
                        let mask = (1 << $bits) - 1;
                        self.0 &= !(mask << $offset);
                        if $addr {
                            self.0 |= ((new_field as $total_bits) & (mask << $offset))
                        } else {
                            self.0 |= (((new_field as $total_bits) & mask) << $offset);
                        }

                        
                    }
                )*
            )*
            
            #[inline]
            pub fn get_type(&self) -> usize {
                let mask = (1 << $type_bits) - 1;
                let value = ((self.0 >> $type_offset) & mask) as usize;
                value
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

pub struct ListQueue {
    pub head: usize,
    pub tail: usize,
}