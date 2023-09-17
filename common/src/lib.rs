#![no_std]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![feature(linkage)]

pub mod sel4_config;
pub mod structures;
pub mod utils;
pub mod sbi;
mod console;
pub mod logging;
pub mod message_info;
pub mod object;
pub mod fault;
