pub mod handler;
use core::arch::asm;

use common::{BIT, utils::convert_to_mut_type_ref};
use cspace::interface::cte_t;
use vspace::pptr_t;

use crate::{config::*, riscv::read_sip};

#[no_mangle]
pub static mut intStateIRQTable: [usize; 2] = [0; 2];

pub static mut intStateIRQNode: pptr_t = 0;

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut active_irq: [usize; 1] = [0; 1];

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum IRQState {
    IRQInactive = 0,
    IRQSignal = 1,
    IRQTimer = 2,
    IRQReserved = 3,
}

#[inline]
pub fn get_irq_state(irq: usize) -> IRQState {
    unsafe {
        core::mem::transmute::<u8, IRQState>(intStateIRQTable[irq] as u8)
    }
}

#[inline]
pub fn get_irq_handler_slot(irq: usize) -> &'static mut cte_t {
    unsafe {
        convert_to_mut_type_ref::<cte_t>(intStateIRQNode).get_offset_slot(irq)
    }
}

pub fn deletingIRQHandler(irq: usize) {
    get_irq_handler_slot(irq).delete_one()
}

#[inline]
pub fn set_irq_state(state: IRQState, irq: usize) {
    unsafe {
        intStateIRQTable[irq] = state as usize;
        mask_interrupt(state == IRQState::IRQInactive, irq)
    }
}

#[no_mangle]
pub fn setIRQState(state: IRQState, irq: usize) {
    unsafe {
        intStateIRQTable[irq] = state as usize;
        mask_interrupt(state == IRQState::IRQInactive, irq);
    }
}

#[no_mangle]
pub extern "C" fn intStateIRQNodeToR(ptr: *mut usize) {
    unsafe {
        intStateIRQNode = ptr as usize;
    }
}

#[no_mangle]
pub fn deletedIRQHandler(irq: usize) {
    setIRQState(IRQState::IRQInactive, irq);
}
#[inline]
pub fn set_sie_mask(mask_high: usize) {
    unsafe {
        let _temp: usize;
        asm!("csrrs {0},sie,{1}",out(reg)_temp,in(reg)mask_high);
    }
}
#[inline]
pub fn clear_sie_mask(mask_low: usize) {
    unsafe {
        let _temp: usize;
        asm!("csrrc {0},sie,{1}",out(reg)_temp,in(reg)mask_low);
    }
}

#[inline]
pub fn mask_interrupt(disable: bool, irq: usize) {
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

#[no_mangle]
pub fn ackInterrupt(_irq: usize) {
    unsafe {
        active_irq[0] = irqInvalid;
    }
}

#[inline]
pub fn is_irq_active(irq: usize) -> bool {
    get_irq_state(irq) == IRQState::IRQInactive
}

#[no_mangle]
pub fn isIRQActive(_irq: usize) -> bool {
    panic!("should not be invoked!")
}

#[inline]
#[no_mangle]
pub fn getActiveIRQ() -> usize {
    let mut irq = unsafe { active_irq[0] };
    if IS_IRQ_VALID(irq) {
        return irq;
    }

    let sip = read_sip();
    if (sip & BIT!(SIP_SEIP)) != 0 {
        irq = 0;
    } else if (sip & BIT!(SIP_STIP)) != 0 {
        irq = KERNEL_TIMER_IRQ;
    } else {
        irq = irqInvalid;
    }
    unsafe {
        active_irq[0] = irq;
    }
    return irq;
}

#[no_mangle]
pub fn initIRQController(arr: *mut i32, size: usize) {
    unsafe {
        let data = core::slice::from_raw_parts_mut(arr, size);
        for i in 0..size {
            data[i] = 0;
        }
    }
}

pub fn IS_IRQ_VALID(x: usize) -> bool {
    (x <= maxIRQ) && (x != irqInvalid)
}