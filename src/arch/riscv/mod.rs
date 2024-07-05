mod c_traps;
mod exception;
mod platform;

pub use c_traps::restore_user_context;
use core::arch::asm;
pub use platform::{init_cpu, init_freemem};

use crate::config::RESET_CYCLES;
use sel4_common::arch::set_timer;

core::arch::global_asm!(include_str!("restore_fp.S"));

pub fn read_stval() -> usize {
    let temp: usize;
    unsafe {
        asm!("csrr {}, stval",out(reg)temp);
    }
    temp
}

pub fn read_sip() -> usize {
    let temp: usize;
    unsafe {
        asm!("csrr {}, sip",out(reg)temp);
    }
    temp
}

pub fn read_time() -> usize {
    let temp: usize;
    unsafe {
        asm!("rdtime {}",out(reg)temp);
    }
    temp
}

pub fn read_scause() -> usize {
    let temp: usize;
    unsafe {
        asm!("csrr {}, scause",out(reg)temp);
    }
    temp
}

#[no_mangle]
pub fn resetTimer() {
    let mut target = read_time() + RESET_CYCLES;
    set_timer(target);
    while read_time() > target {
        target = read_time() + RESET_CYCLES;
        set_timer(target);
    }
}
