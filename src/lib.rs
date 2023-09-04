#![no_std]
#![crate_type = "staticlib"]
#![feature(core_intrinsics)]
#![no_main]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(while_true)]
#![allow(unused_assignments)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![feature(stdsimd)]


extern crate core;

use core::arch::asm;


use common::sbi::shutdown;

mod config;
// mod console;
mod lang_items;
mod utils;
mod kernel;
mod structures;
mod object;
mod riscv;
mod syscall;
mod boot;
mod sbi;

#[no_mangle]
pub extern "C" fn idle_thread() {
    while true {
        unsafe {
            asm!("wfi");
        }
    }
}

#[no_mangle]
pub extern "C" fn halt() {
    shutdown()
}

#[no_mangle]
pub extern "C" fn strnlen(str: *const u8, _max_len: usize) -> usize {
    unsafe {
        let mut c = str;
        let mut ans = 0;
        while (*c) != 0 {
            ans += 1;
            c = c.add(1);
        }
        ans
    }
}
