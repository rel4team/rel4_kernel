
use cspace::interface::*;


//cap relevant

#[inline]
pub fn cap_get_max_free_index(cap: &cap_t) -> usize {
    let ans = cap_untyped_cap_get_capBlockSize(cap);
    let sel4_MinUntypedbits: usize = 4;
    (1usize << ans) - sel4_MinUntypedbits
}
