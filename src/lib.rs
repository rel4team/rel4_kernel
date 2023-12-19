#![no_std]
#![crate_type = "staticlib"]
#![feature(core_intrinsics)]
#![no_main]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(while_true)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![feature(stdsimd)]
#![feature(linkage)]
#![feature(generic_const_exprs)]
#![feature(waker_getters)]

extern crate core;
extern crate alloc;

use common::sbi::shutdown;
mod config;
mod debug;
mod lang_items;
mod utils;
mod kernel;
mod structures;
mod object;
mod riscv;
mod syscall;
mod boot;
mod sbi;
mod interrupt;
mod exception;
mod common;
mod task_manager;
mod vspace;
mod cspace;
mod deps;
#[cfg(feature = "ENABLE_SMP")]
mod smp;

#[cfg(feature = "ENABLE_UINTC")]
mod uintc;

#[cfg(feature = "ENABLE_UINTC")]
mod uintr;





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
