//! This crate implements the IPC mechanism of seL4, including the endpoint, notification, and transfer.
//! 
//! See more details in ../doc.md
#![feature(core_intrinsics)]
#![no_std]
#![allow(internal_features)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

mod endpoint;
mod notification;
mod transfer;

pub use endpoint::*;
pub use notification::*;
pub use transfer::*;
