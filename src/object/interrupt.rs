use core::arch::asm;

use crate::{
    config::{IRQInactive, KERNEL_TIMER_IRQ, SIE_STIE},
    BIT,
};

pub static mut intStateIRQTable: usize = 0;

#[no_mangle]
pub extern "C" fn intStateIRQTableToR(ptr: *mut usize) {
    unsafe {
        intStateIRQTable = ptr as usize;
    }
}

#[inline]
pub fn set_sie_mask(mask_high: usize) {
    unsafe {
        let temp: usize;
        asm!("csrrs {0},sie,{1}",out(reg)temp,in(reg)mask_high);
    }
}
#[inline]
pub fn clear_sie_mask(mask_low: usize) {
    unsafe {
        let temp: usize;
        asm!("csrrc {0},sie,{1}",out(reg)temp,in(reg)mask_low);
    }
}

#[inline]
pub fn maskInterrupt(disable: bool, irq: usize) {
    if irq == KERNEL_TIMER_IRQ {
        if disable {
            clear_sie_mask(BIT!(SIE_STIE));
        } else {
            set_sie_mask(BIT!(SIE_STIE));
        }
    }
}

pub fn setIRQState(irqState: usize, irq: usize) {
    unsafe {
        let ptr = intStateIRQTable as *mut usize;
        *ptr.add(irq) = irqState;
    }
    maskInterrupt(irqState == IRQInactive, irq);
}
