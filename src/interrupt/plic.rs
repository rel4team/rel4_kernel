use log::debug;
use lazy_static::*;
use crate::config::{IRQConst, irqInvalid};
use rv_plic::{Priority, PLIC};
use crate::common::sel4_config::PPTR_BASE_OFFSET;
use crate::common::utils::cpu_id;
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

impl PlicTrait for RVPlic {
    #[cfg(feature = "board_qemu")]
    fn get_claim() -> usize {
        let hart_id = cpu_index_to_id(cpu_id());
        let context = get_context(hart_id, 'S');
        let mut kernel_irq = irqInvalid;
        if let Some(irq) = RVPlic::claim(context) {
            kernel_irq = match irq {
                8 => IRQConst::PLIC_NET as usize,
                _ => irqInvalid
            };
            RVPlic::complete(context, irq);
            // debug!("[get_claim] irq: {}", irq);
        }
        kernel_irq
    }
    #[cfg(feature = "board_qemu")]
    fn mask_irq(disable: bool, irq: usize) {
        if irq == IRQConst::PLIC_NET as usize {
            let hart_id = cpu_index_to_id(cpu_id());
            let context = get_context(hart_id, 'S');
            if disable {
                RVPlic::disable(context, 8);
                debug!("disable net interrupt");
            } else {
                RVPlic::enable(context, 8);
                debug!("enable net interrupt");
            }
        }
    }

    #[cfg(feature = "board_qemu")]
    fn init_hart() {
        let hart_id = cpu_index_to_id(cpu_id());
        let context = get_context(hart_id, 'S');
        for irq in 1..=8 {
            RVPlic::enable(context, irq);
            RVPlic::claim(context);
            RVPlic::complete(context, irq);
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
}

pub type RV_PLIC = RVPlic;
