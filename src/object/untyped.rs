use crate::{
    config::{seL4_MinUntypedBits, CONFIG_RESET_CHUNK_BITS},
    kernel::boot::clearMemory,
    structures::{cap_t, cte_t, exception_t},
    BIT, MASK, ROUND_DOWN,
};

use super::structure_gen::{
    cap_untyped_cap_get_capBlockSize, cap_untyped_cap_get_capFreeIndex,
    cap_untyped_cap_get_capIsDevice, cap_untyped_cap_get_capPtr, cap_untyped_cap_set_capFreeIndex,
};

pub fn alignUp(baseValue: usize, alignment: usize) -> usize {
    (baseValue + BIT!(alignment) - 1) & !MASK!(alignment)
}

pub fn MAX_FREE_INDEX(sizeBits: usize) -> usize {
    BIT!(sizeBits) - seL4_MinUntypedBits
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

// #[no_mangle]
// pub fn resetUntypedCap(srcSlot: *mut cte_t) -> exception_t {
//     unsafe {
//         let prev_cap = (*srcSlot).cap;
//         let block_size = cap_untyped_cap_get_capBlockSize(&prev_cap);
//         let regionBase = cap_untyped_cap_get_capPtr(&prev_cap);
//         let chunk = CONFIG_RESET_CHUNK_BITS;
//         let offset = FREE_INDEX_TO_OFFSET(cap_untyped_cap_get_capFreeIndex(&prev_cap));
//         let deviceMemory = cap_untyped_cap_get_capIsDevice(&prev_cap);
//         if offset == 0 {
//             return exception_t::EXCEPTION_NONE;
//         }

//         if deviceMemory != 0 && block_size < chunk {
//             if deviceMemory != 0 {
//                 clearMemory(regionBase as *mut u8, block_size);
//             }
//             (*srcSlot).cap = cap_untyped_cap_set_capFreeIndex(&mut prev_cap, 0) as *mut cap_t;
//         } else {
//             let mut offset: isize = ROUND_DOWN!(offset - 1, chunk) as isize;
//             //FIXEME::why - BIT??
//             while offset != -(BIT!(chunk) as isize) {
//                 clearMemory(
//                     GET_OFFSET_FREE_PTR(regionBase, offset as usize) as *mut u8,
//                     chunk,
//                 );
//                 offset -= BIT!(chunk) as isize;
//             }
//             (*srcSlot).cap = cap_untyped_cap_set_capFreeIndex(
//                 &mut prev_cap,
//                 OFFSET_TO_FREE_IDNEX(offset as usize),
//             ) as *mut cap_t;
//         }
//         exception_t::EXCEPTION_NONE
//     }
// }
