#![no_std]
#![crate_type = "staticlib"]
#![feature(core_intrinsics)]
#![feature(const_option)]
#![feature(const_nonnull_new)]
#![no_main]
#![allow(internal_features)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![feature(linkage)]

extern crate core;
use sel4_common::arch::shutdown;
mod config;
// mod console;
mod arch;
mod boot;
mod interrupt;
mod kernel;
mod lang_items;
mod object;
mod structures;
mod syscall;
mod utils;

mod compatibility;
mod ffi;
mod interfaces_impl;

pub use sel4_common::{plus_define_bitfield, BIT, IS_ALIGNED, MASK, ROUND_DOWN, ROUND_UP};

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
