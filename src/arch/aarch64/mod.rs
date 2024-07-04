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

pub extern "C" fn write_stvec(_val: usize) {
    // unsafe {
    //     asm!("csrw stvec , {}",in(reg) val);
    // }
    todo!("write_stvec")
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

pub fn read_sepc() -> usize {
    // let temp: usize;
    // unsafe {
    //     asm!("csrr {}, sepc",out(reg)temp);
    // }
    // temp
    todo!("read_sepc")
}

pub fn read_sstatus() -> usize {
    // let temp: usize;
    // unsafe {
    //     asm!("csrr {}, sstatus",out(reg)temp);
    // }
    // temp
    todo!("read_sstatus")
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
