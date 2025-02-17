#![no_std]
#![allow(unused)]
mod lq;

pub use lq::LocalQueue;
use taic_pac::taic::RegisterBlock;

#[derive(Debug, Clone, Copy)]
pub struct Taic {
    base: usize,
    lq_num: usize,
}

impl Taic {
    pub const fn new(base: usize, lq_num: usize) -> Self {
        Self { base, lq_num }
    }

    pub fn regs(&self) -> &'static RegisterBlock {
        unsafe { &*(self.base as *const RegisterBlock) }
    }

    pub fn alloc_lq(&self, osid: usize, processid: usize) -> Option<LocalQueue> {
        let alq = self.regs().alq();
        alq.write(|w| unsafe { w.bits(osid as _) });
        alq.write(|w| unsafe { w.bits(processid as _) });
        let idx = alq.read().bits() as usize;
        if idx == usize::MAX {
            None
        } else {
            let gq_idx = (idx >> 32) & 0xffffffff;
            let lq_idx = idx & 0xffffffff;
            let lq_base = self.base + 0x1000 + (gq_idx * self.lq_num + lq_idx) * 0x1000;
            Some(LocalQueue::new(lq_base, self.clone()))
        }
    }

    pub fn sim_extint(&self, irq: usize) {
        self.regs().sim_extint(irq).sim_extint().write(|w| unsafe { w.bits(1 as _) });
    }
}
