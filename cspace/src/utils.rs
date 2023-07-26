use common::{sel4_config::seL4_MinUntypedBits, BIT};


pub fn MAX_FREE_INDEX(bits: usize) -> usize {
    BIT!(bits - seL4_MinUntypedBits)
}