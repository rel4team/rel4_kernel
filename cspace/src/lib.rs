#![feature(core_intrinsics)]
#![no_std]
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

extern crate core;
mod cap;
mod utils;
mod mdb;
mod cte;
mod cap_rights;

pub mod interface;