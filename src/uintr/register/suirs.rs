//! suirs register

use bit_field::BitField;

pub struct Suirs {
    bits: usize,
}

impl Suirs {
    /// Returns the contents of the register as raw bits
    #[inline]
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// User-interrupt enabled.
    #[inline]
    pub fn enabled(&self) -> bool {
        self.bits.get_bit(63)
    }

    /// Table size.
    pub fn index(&self) -> usize {
        self.bits.get_bits(0..16)
    }
}

read_csr_as!(Suirs, 0x1B1);
write_csr_as_usize!(0x1B1);
