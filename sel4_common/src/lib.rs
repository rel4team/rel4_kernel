//! This crate contains the common code for the seL4 kernel.
//! Such as the seL4 kernel configuration(`Registers`, `Constants`), the seL4 structures(`MessageInfo`, `ObjectType`, `Error`, 'Exception', 'Fault'), and the seL4 utils(`Logging`, `SBI`).
#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub mod arch;
mod console;
pub mod fault;
mod ffi;
pub mod logging;
pub mod message_info;
pub mod object;
pub mod sel4_config;
#[cfg(feature = "ENABLE_SMP")]
pub mod smp;
pub mod structures;
pub mod utils;
