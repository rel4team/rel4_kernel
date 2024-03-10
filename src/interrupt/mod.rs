pub mod handler;
mod plic;
use core::arch::asm;
use core::ops::Deref;
use log::debug;


use crate::common::sel4_config::CONFIG_MAX_NUM_NODES;
use crate::common::utils::{convert_to_mut_type_ref, cpu_id};
use crate::BIT;
use crate::cspace::interface::cte_t;
use crate::vspace::pptr_t;

use crate::{config::*, riscv::read_sip};

#[cfg(feature = "ENABLE_SMP")]
use crate::deps::{ipi_clear_irq, ipi_get_irq};
use crate::interrupt::plic::{RV_PLIC, PlicTrait};

#[no_mangle]
pub static mut intStateIRQTable: [usize; maxIRQ + 1] = [0; maxIRQ + 1];

pub static mut intStateIRQNode: pptr_t = 0;

#[no_mangle]
#[link_section = ".boot.bss"]
pub static mut active_irq: [usize; CONFIG_MAX_NUM_NODES] = [0; CONFIG_MAX_NUM_NODES];

#[cfg(feature = "ENABLE_SMP")]
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum IRQState {
    IRQInactive = 0,
    IRQSignal = 1,
    IRQTimer = 2,
    IRQIPI = 3,
    IRQReserved = 4,
}

#[cfg(not(feature = "ENABLE_SMP"))]
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
    } else {
        RV_PLIC::mask_irq(disable, irq);
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
pub fn ackInterrupt(irq: usize) {
    unsafe {
        active_irq[cpu_id()] = irqInvalid;
    }
    if irq == KERNEL_TIMER_IRQ {
        return;
    }
    #[cfg(feature = "ENABLE_SMP")] {
        if irq == IRQConst::INTERRUPT_IPI_0 as usize || irq == IRQConst::INTERRUPT_IPI_1 as usize {
            unsafe { ipi_clear_irq(irq); }
        }
    }
}

#[inline]
pub fn is_irq_active(irq: usize) -> bool {
    get_irq_state(irq) != IRQState::IRQInactive
}

#[no_mangle]
pub fn isIRQActive(_irq: usize) -> bool {
    panic!("should not be invoked!")
}

#[inline]
#[no_mangle]
pub fn getActiveIRQ() -> usize {
    let mut irq = unsafe { active_irq[cpu_id()] };
    if IS_IRQ_VALID(irq) {
        return irq;
    }

    let sip = read_sip();
    #[cfg(feature = "ENABLE_SMP")] {
        use crate::common::sbi::clear_ipi;
        if (sip & BIT!(SIP_SEIP)) != 0 {
            // irq = IRQConst::PLIC_NET as usize;
            irq = RV_PLIC::get_claim();
        } else if (sip & BIT!(SIP_SSIP)) != 0 {
            clear_ipi();
            irq = unsafe { ipi_get_irq() };
            // debug!("irq: {}", irq);
        } else if (sip & BIT!(SIP_STIP)) != 0 {
            irq = KERNEL_TIMER_IRQ;
        }
        else {
            irq = irqInvalid;
        }
    }
    #[cfg(not(feature = "ENABLE_SMP"))]
    if (sip & BIT!(SIP_SEIP)) != 0 {
        irq = 0;
    } else if (sip & BIT!(SIP_STIP)) != 0 {
        irq = KERNEL_TIMER_IRQ;
    }
    else {
        irq = irqInvalid;
    }
    unsafe {
        active_irq[cpu_id()] = irq;
    }
    return irq;
}
pub fn IS_IRQ_VALID(x: usize) -> bool {
    (x <= maxIRQ) && (x != irqInvalid)
}

pub fn init_irq_controller() {
    debug!("Initializing PLIC...");
    for i in 0..CONFIG_MAX_NUM_NODES {
        unsafe { active_irq[i] = irqInvalid; }
    }
    // RV_PLIC::init_controller();
}

pub fn init_hart() {
    RV_PLIC::init_hart();
}