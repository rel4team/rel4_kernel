use core::arch::asm;

use crate::{
    config::{IRQInactive, KERNEL_TIMER_IRQ, SIE_STIE, SIP_SEIP, SIP_STIP},
    riscv::read_sip,
    structures::cte_t,
    BIT,
};

#[no_mangle]
pub static mut intStateIRQTable: [usize; 2] = [0; 2];

pub static mut intStateIRQNode: usize = 0;

#[no_mangle]
pub extern "C" fn intStateIRQNodeToR(ptr: *mut usize) {
    unsafe {
        intStateIRQNode = ptr as usize;
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

pub fn isIRQPending() -> bool {
    let sip = read_sip();
    if (sip & (BIT!(SIP_STIP) | BIT!(SIP_SEIP))) != 0 {
        true
    } else {
        false
    }
}

#[link(name = "kernel_all.c")]
extern "C" {
    fn cteDeleteOne(c: *mut cte_t);
}

#[no_mangle]
pub fn deletingIRQHandler(irq: usize) {
    unsafe {
        let slot = (intStateIRQNode as *mut cte_t).add(irq);
        cteDeleteOne(slot);
    }
}

#[no_mangle]
pub fn setIRQState(state: usize, irq: usize) {
    unsafe {
        intStateIRQTable[irq] = state;
        maskInterrupt(state == 0, irq);
    }
}
