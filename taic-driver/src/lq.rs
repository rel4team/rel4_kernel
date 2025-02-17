use taic_pac::taic::Lq_;

use crate::Taic;

pub struct LocalQueue {
    base: usize,
    taic: Taic,
}

impl LocalQueue {
    pub fn new(base: usize, taic: Taic) -> Self {
        Self { base, taic }
    }

    pub fn regs(&self) -> &'static Lq_ {
        unsafe { &*(self.base as *const Lq_) }
    }

    pub fn task_enqueue(&self, taskid: usize) {
        &self
            .regs()
            .task_enqueue()
            .write(|w| unsafe { w.bits(taskid as _) });
        log::info!("{:#x}, task_enqueue: {:#X}", self.queue_idx(), taskid);
    }

    pub fn task_dequeue(&self) -> Option<usize> {
        let taskid = self.regs().task_dequeue().read().bits() as usize;
        log::info!("{:#x}, task_dequeue: {:#X}", self.queue_idx(), taskid);
        if taskid == 0 {
            None
        } else {
            Some(taskid)
        }
    }

    pub fn register_sender(&self, recv_os: usize, recv_proc: usize) {
        &self
            .regs()
            .register_sender()
            .write(|w| unsafe { w.bits(recv_os as _) });
        &self
            .regs()
            .register_sender()
            .write(|w| unsafe { w.bits(recv_proc as _) });
    }

    pub fn cancel_sender(&self, recv_os: usize, recv_proc: usize) {
        &self
            .regs()
            .cancel_sender()
            .write(|w| unsafe { w.bits(recv_os as _) });
        &self
            .regs()
            .cancel_sender()
            .write(|w| unsafe { w.bits(recv_proc as _) });
    }

    pub fn register_receiver(&self, send_os: usize, send_proc: usize, handler: usize) {
        &self
            .regs()
            .register_receiver()
            .write(|w| unsafe { w.bits(send_os as _) });
        &self
            .regs()
            .register_receiver()
            .write(|w| unsafe { w.bits(send_proc as _) });
        &self
            .regs()
            .register_receiver()
            .write(|w| unsafe { w.bits(handler as _) });
    }

    pub fn send_intr(&self, recv_os: usize, recv_proc: usize) {
        &self
            .regs()
            .send_intr()
            .write(|w| unsafe { w.bits(recv_os as _) });
        &self
            .regs()
            .send_intr()
            .write(|w| unsafe { w.bits(recv_proc as _) });
    }

    pub fn whart(&self, hartid: usize) {
        &self
            .regs()
            .whart()
            .write(|w| unsafe { w.bits(hartid as _) });
    }

    pub fn register_extintr(&self, irq: usize, handler: usize) {
        &self
            .regs()
            .register_extint(irq)
            .register_extint().write(|w| unsafe { w.bits(handler as _) });
    }

    fn queue_idx(&self) -> usize {
        let queue_idx = (self.base - self.taic.base - 0x1000) / 0x1000;
        let gq_idx = queue_idx / self.taic.lq_num;
        let lq_idx = queue_idx % self.taic.lq_num;
        (gq_idx << 32) | lq_idx
    }
}

impl Drop for LocalQueue {
    fn drop(&mut self) {
        let flq = self.taic.regs().flq();
        log::info!("free local queue {:#x}", self.queue_idx());
        flq.write(|w| unsafe { w.bits(self.queue_idx() as _) });
    }
}
