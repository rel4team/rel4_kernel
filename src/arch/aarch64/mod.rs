mod c_traps;
mod exception;
mod ffi;
mod platform;

pub mod arm_gic;

use crate::config::RESET_CYCLES;
pub use c_traps::restore_user_context;
pub use platform::{cleanInvalidateL1Caches, init_cpu, init_freemem, invalidateLocalTLB};
use sel4_common::arch::set_timer;

pub fn read_stval() -> usize {
    // let temp: usize;
    // unsafe {
    //     asm!("csrr {}, stval",out(reg)temp);
    // }
    // temp
    todo!("read_stval")
}

pub fn read_sip() -> usize {
    // let temp: usize;
    // unsafe {
    //     asm!("csrr {}, sip",out(reg)temp);
    // }
    // temp
    todo!("read_sip")
}

pub fn read_time() -> usize {
    // let temp: usize;
    // unsafe {
    //     asm!("rdtime {}",out(reg)temp);
    // }
    // temp
    todo!("read_time")
}

pub fn read_scause() -> usize {
    // let temp: usize;
    // unsafe {
    //     asm!("csrr {}, scause",out(reg)temp);
    // }
    // temp
    todo!("read_scause")
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
