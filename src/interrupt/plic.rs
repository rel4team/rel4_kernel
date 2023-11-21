use log::debug;
use lazy_static::*;
use crate::config::irqInvalid;

pub trait PlicTrait {
    fn get_claim(&self) -> usize {
        debug!("no PLIC present, can't claim any interrupt");
        irqInvalid
    }

    fn complete_claim(&self, irq: usize) {
        debug!("no PLIC present, can't complete claim for interrupt {}", irq);
    }

    fn mask_irq(&self, disable: bool, irq: usize) {
        debug!("no PLIC present, can't {} interrupt {}",
            if disable { "mask" } else { "unmask" }, irq);
    }

    fn irq_set_trigger(&self, irq: usize, edge_triggered: bool) {
        debug!("no PLIC present, can't set interrupt {} to {} triggered",
            irq, if edge_triggered { "edge" } else { "level" });
    }

    fn init_hart(&self) {
        debug!("no PLIC present, skip hart specific initialisation");
    }

    fn init_controller(&self) {
        debug!("no PLIC present, skip platform specific initialisation");
    }
}

pub struct DefaultPlic;
impl PlicTrait for DefaultPlic {}

lazy_static! {
    pub static ref PLIC: DefaultPlic = DefaultPlic;
}
