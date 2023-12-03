#![no_std]
#![allow(unused)]

mod register;
mod uipi;


pub use register::*;
pub use uipi::*;

pub unsafe fn uret() {
    core::arch::asm!("uret");
}