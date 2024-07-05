//! This crate provides task management for seL4, including the TCB, scheduler, and thread relevant structures.
//!
//!  See more details in ../doc.md

#![feature(core_intrinsics)]
#![no_std]
#![allow(internal_features)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

mod deps;
mod scheduler;
mod structures;
pub mod tcb;
mod tcb_queue;
mod thread_state;

pub use scheduler::*;
pub use structures::*;
pub use tcb::*;
pub use tcb_queue::*;
pub use thread_state::*;
