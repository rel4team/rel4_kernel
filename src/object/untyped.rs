

use common::{sel4_config::*, BIT, MASK};

pub fn alignUp(baseValue: usize, alignment: usize) -> usize {
    (baseValue + BIT!(alignment) - 1) & !MASK!(alignment)
}

pub fn FREE_INDEX_TO_OFFSET(freeIndex: usize) -> usize {
    freeIndex << seL4_MinUntypedBits
}
pub fn GET_FREE_REF(base: usize, freeIndex: usize) -> usize {
    base + FREE_INDEX_TO_OFFSET(freeIndex)
}
pub fn GET_FREE_INDEX(base: usize, free: usize) -> usize {
    free - base >> seL4_MinUntypedBits
}
pub fn GET_OFFSET_FREE_PTR(base: usize, offset: usize) -> *mut usize {
    (base + offset) as *mut usize
}
pub fn OFFSET_TO_FREE_IDNEX(offset: usize) -> usize {
    offset >> seL4_MinUntypedBits
}

