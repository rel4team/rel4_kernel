use alloc::vec::Vec;
use lazy_init::LazyInit;
use log::debug;
use taic_driver::{LocalQueue, Taic};
use crate::common::utils::cpu_id;

const TAIC_BASE: usize = axconfig::PHYS_VIRT_OFFSET + axconfig::MMIO_REGIONS[1].0;
const LQ_NUM: usize = 8;
const TAIC: Taic = Taic::new(TAIC_BASE, LQ_NUM);
static mut START: usize = 0;
static mut INT_LATENCY: Vec<usize> = Vec::new();
const NUM: usize = 1000;
static LQ: LazyInit<LocalQueue> = LazyInit::new();

fn enq_deq_test() {
    debug!("Start Taic enq & deq test ...");
    let lq0 = TAIC.alloc_lq(1, 2).unwrap();
    let mut enq_cycles = Vec::new();
    let mut deq_cycles = Vec::new();
    for i in 0..NUM {
        let enq_start = riscv::register::cycle::read();
        lq0.task_enqueue(i);
        let enq_end = riscv::register::cycle::read();
        enq_cycles.push(enq_end - enq_start);
    }
    for _i in 0..NUM {
        let deq_start = riscv::register::cycle::read();
        let c = lq0.task_dequeue();
        let deq_end = riscv::register::cycle::read();
        deq_cycles.push(c);
    }
    debug!("Enq cycles: {:?}", enq_cycles);
    debug!("---------------------------------");
    debug!("Deq cycles: {:?}", deq_cycles);
}

fn sexint_latency_test() {
    debug!("Start Taic software interrupt test ...");
    let lq0 = TAIC.alloc_lq(1, 0).unwrap();
    LQ.init_by(lq0);
    LQ.whart(cpu_id());

    // axhal::irq::register_handler(axhal::platform::irq::SOFT_IRQ_NUM, || {
    //     let end = riscv::register::cycle::read();
    //     unsafe { INT_LATENCY.push(end - START) };
    //     log::trace!("software interrupt {} {}", unsafe { START }, end);
    //     LQ.task_dequeue();
    // });

    let mut send_extintr_latency = Vec::new();
    for _ in 0..NUM {
        let start = riscv::register::cycle::read();
        TAIC.sim_extint(0);
        let end = riscv::register::cycle::read();
        send_extintr_latency.push(end - start);
    }
    debug!("Send extintr latencys: {:?}", send_extintr_latency);
    debug!("---------------------------------");
    for _ in 0..NUM {
        LQ.register_extintr(0, 0x109);
        unsafe { START = riscv::register::cycle::read() };
        TAIC.sim_extint(0);
    }

    debug!("Int latencys: {:?}", unsafe { INT_LATENCY.clone() });
}


pub fn start() {
    // enq_deq_test();
    // // sexint_latency_test();

    // loop {
    
    // }
}
