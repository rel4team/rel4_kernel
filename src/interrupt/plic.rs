use log::debug;
use lazy_static::*;
use crate::config::{IRQConst, irqInvalid};
use rv_plic::{Priority, PLIC};
use crate::common::sel4_config::PPTR_BASE_OFFSET;
use crate::common::utils::cpu_id;
use crate::config::IRQConst::PLIC_NET;

#[cfg(feature = "ENABLE_SMP")]
use crate::smp::cpu_index_to_id;

pub trait PlicTrait {
    fn get_claim() -> usize {
        debug!("no PLIC present, can't claim any interrupt");
        irqInvalid
    }

    fn complete_claim(irq: usize) {
        debug!("no PLIC present, can't complete claim for interrupt {}", irq);
    }

    fn mask_irq(disable: bool, irq: usize) {
        debug!("no PLIC present, can't {} interrupt {}",
            if disable { "mask" } else { "unmask" }, irq);
    }

    fn irq_set_trigger(irq: usize, edge_triggered: bool) {
        debug!("no PLIC present, can't set interrupt {} to {} triggered",
            irq, if edge_triggered { "edge" } else { "level" });
    }

    fn init_hart() {
        debug!("no PLIC present, skip hart specific initialisation");
    }

    fn init_controller() {
        debug!("no PLIC present, skip platform specific initialisation");
    }
}

pub struct DefaultPlic;
impl PlicTrait for DefaultPlic {}


pub const PLIC_BASE: usize = 0xc00_0000 + PPTR_BASE_OFFSET;
pub const PLIC_PRIORITY_BIT: usize = 3;

pub type RVPlic = PLIC<{ PLIC_BASE }, { PLIC_PRIORITY_BIT }>;

pub fn get_context(hart_id: usize, mode: char) -> usize {
    const MODE_PER_HART: usize = 3;
    hart_id * MODE_PER_HART
        + match mode {
        'M' => 0,
        'S' => 1,
        'U' => 2,
        _ => panic!("Wrong Mode"),
    }
}

const CPU_IDX: usize = 0;

fn get_hart_id(cpu_idx: usize) -> usize {
    #[cfg(feature = "ENABLE_SMP")] {
        crate::smp::cpu_index_to_id(cpu_idx)
    }
    #[cfg(not(feature = "ENABLE_SMP"))]
    0
}

impl PlicTrait for RVPlic {
    #[cfg(feature = "board_qemu")]
    fn get_claim() -> usize {
        // debug!("get_claim");
        let mut kernel_irq = irqInvalid;
        let hart_id = get_hart_id(CPU_IDX);
        let context = get_context(hart_id, 'S');

        if let Some(irq) = RVPlic::claim(context) {
            // debug!("[get_claim] irq: {}", irq);
            kernel_irq = match irq {
                8 => PLIC_NET as usize,
                _ => irqInvalid
            };
            RVPlic::complete(context, irq);
            // debug!("[get_claim] irq: {}", irq);
        }
        kernel_irq
    }

    #[cfg(feature = "board_lrv")]
    fn get_claim() -> usize {
        let mut kernel_irq = irqInvalid;
        let hart_id = get_hart_id(CPU_IDX);
        let context = get_context(hart_id, 'S');

        if let Some(irq) = RVPlic::claim(context) {
            kernel_irq = match irq {
                3 => PLIC_NET as usize,
                _ => irqInvalid
            };
            // RVPlic::complete(context, irq);
            // debug!("[get_claim] irq: {}", irq);
        }
        kernel_irq
    }
    #[cfg(feature = "board_qemu")]
    fn mask_irq(disable: bool, irq: usize) {
        if irq == PLIC_NET as usize {
            let hart_id = get_hart_id(CPU_IDX);
            let context = get_context(hart_id, 'S');
            if disable {
                RVPlic::disable(context, 8);
                debug!("disable net interrupt: {}", hart_id);
            } else {
                RVPlic::enable(context, 8);
                debug!("enable net interrupt: {}", hart_id);
            }
        }
    }

    #[cfg(feature = "board_lrv")]
    fn mask_irq(disable: bool, irq: usize) {
        if irq == PLIC_NET as usize {
            let hart_id = get_hart_id(CPU_IDX);
            let context = get_context(hart_id, 'S');
            if disable {
                RVPlic::disable(context, 3);
                debug!("[board_lrv]disable net interrupt: {}", hart_id);
            } else {
                RVPlic::enable(context, 3);
                RVPlic::claim(context);
                RVPlic::complete(context, 3);
                debug!("[board_lrv]enable net interrupt: {}", hart_id);
            }
        }
    }

    #[cfg(feature = "board_qemu")]
    fn init_hart() {
        let hart_id = get_hart_id(cpu_id());
        let context = get_context(hart_id, 'S');
        for irq in 1..=8 {
            RVPlic::disable(context, irq);
        }
        RVPlic::set_threshold(context, Priority::any());
    }

    #[cfg(feature = "board_lrv")]
    fn init_hart() {
        let hart_id = get_hart_id(cpu_id());
        let context = get_context(hart_id, 'S');
        for irq in 1..=6 {
            RVPlic::enable(context, irq);
            RVPlic::claim(context);
            RVPlic::complete(context, irq);
            RVPlic::disable(context, irq);
        }
        RVPlic::set_threshold(context, Priority::any());
        RVPlic::clear_enable(get_context(hart_id, 'U'), 0);
        RVPlic::set_threshold(get_context(hart_id, 'M'), Priority::never());
    }

    #[cfg(feature = "board_qemu")]
    fn init_controller() {
        debug!("PLIC_BASE: {:#x}", PLIC_BASE);
        for intr in 1..=8 {
            RVPlic::set_priority(intr, Priority::lowest());
        }
    }

    #[cfg(feature = "board_lrv")]
    fn init_controller() {
        debug!("PLIC_BASE: {:#x}", PLIC_BASE);
        for intr in 1..=6 {
            RVPlic::set_priority(intr, Priority::lowest());
        }
    }
}

pub type RV_PLIC = RVPlic;

#[cfg(feature = "board_qemu")]
pub fn plic_complete_claim(irq: usize) {

}
#[cfg(feature = "board_lrv")]
pub fn plic_complete_claim(irq: usize) {
    let hart_id = get_hart_id(CPU_IDX);
    let context = get_context(hart_id, 'S');
    if irq == PLIC_NET as usize {
        // debug!("plic complete: {}", irq);
        RVPlic::complete(context, 3);
    }
}