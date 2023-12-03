use crate::uintc::config::{UINTC_BASE, UINTC_ENTRY_NUM, UINTC_WIDTH};

pub const UINTC_SEND_OFF: usize = 0x00;
pub const UINTC_LOW_OFF: usize = 0x08;
pub const UINTC_HIGH_OFF: usize = 0x10;
pub const UINTC_ACT_OFF: usize = 0x18;

#[inline(never)]
pub fn uintc_send_uipi(index: usize) {
    assert!(index < UINTC_ENTRY_NUM);
    let pa = UINTC_BASE + index * UINTC_WIDTH + UINTC_SEND_OFF;
    unsafe { *(pa as *mut u64) = 1 };
}
#[inline(never)]
pub fn uintc_read_low(index: usize) -> u64 {
    assert!(index < UINTC_ENTRY_NUM);
    let pa = UINTC_BASE + index * UINTC_WIDTH + UINTC_LOW_OFF;
    unsafe { *(pa as *const u64) }
}
#[inline(never)]
pub fn uintc_write_low(index: usize, data: u64) {
    assert!(index < UINTC_ENTRY_NUM);
    let pa = UINTC_BASE + index * UINTC_WIDTH + UINTC_LOW_OFF;
    unsafe { *(pa as *mut u64) = data };
}
#[inline(never)]
pub fn uintc_read_high(index: usize) -> u64 {
    assert!(index < UINTC_ENTRY_NUM);
    let pa = UINTC_BASE + index * UINTC_WIDTH + UINTC_HIGH_OFF;
    unsafe { *(pa as *const u64) }
}
#[inline(never)]
pub fn uintc_write_high(index: usize, data: u64) {
    assert!(index < UINTC_ENTRY_NUM);
    let pa = UINTC_BASE + index * UINTC_WIDTH + UINTC_HIGH_OFF;
    unsafe { *(pa as *mut u64) = data };
}
#[inline(never)]
pub fn uintc_get_active(index: usize) -> bool {
    assert!(index < UINTC_ENTRY_NUM);
    let pa = UINTC_BASE + index * UINTC_WIDTH + UINTC_ACT_OFF;
    unsafe { *(pa as *const u64) == 0x1 }
}
#[inline(never)]
pub fn uintc_set_active(index: usize) {
    assert!(index < UINTC_ENTRY_NUM);
    let pa = UINTC_BASE + index * UINTC_WIDTH + UINTC_ACT_OFF;
    unsafe { *(pa as *mut u64) = 0x1 };
}