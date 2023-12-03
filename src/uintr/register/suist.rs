//! suist register

use bit_field::BitField;

pub struct Suist {
    bits: usize,
}

impl Suist {
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

    /// Physical page number.
    #[inline]
    pub fn ppn(&self) -> usize {
        self.bits.get_bits(0..44)
    }

    /// Table size.
    pub fn size(&self) -> usize {
        self.bits.get_bits(44..56)
    }
}

read_csr_as!(Suist, 0x1B0);
write_csr_as_usize!(0x1B0);
