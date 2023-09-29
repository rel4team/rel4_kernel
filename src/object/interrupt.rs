use core::intrinsics::unlikely;

use crate::{
    config::maxIRQ,
    riscv::resetTimer,
    interrupt::*,
};

use common::{utils::convert_to_mut_type_ref};

use cspace::compatibility::*;
use cspace::interface::*;
use task_manager::ipc::*;
use task_manager::*;
use log::debug;
#[no_mangle]
pub fn deletedIRQHandler(irq: usize) {
    setIRQState(IRQInactive, irq);
}


#[no_mangle]
pub fn handleInterrupt(irq: usize) {
    if unlikely(irq > maxIRQ) {
        debug!(
            "Received IRQ {}, which is above the platforms maxIRQ of {}\n",
            irq, maxIRQ
        );
        mask_interrupt(true, irq);
        ackInterrupt(irq);
        return;
    }

    unsafe {
        match intStateIRQTable[irq] {
            IRQSignal => {
                let cte_ptr = (intStateIRQNode as *mut cte_t).add(irq);
                let cap = &(*cte_ptr).cap;
                if cap_get_capType(cap) == cap_notification_cap
                    && cap_notification_cap_get_capNtfnCanSend(cap) != 0
                {
                    convert_to_mut_type_ref::<notification_t>(cap.get_nf_ptr()).send_signal(cap.get_nf_badge());
                }
            }
            IRQTimer => {
                timerTick();
                resetTimer();
            }
            IRQReserved => {
                debug!("Received unhandled reserved IRQ: {}\n", irq);
            }
            IRQInactive => {
                mask_interrupt(true, irq);
                debug!("Received disabled IRQ: {}\n", irq);
            }
            _ => {
                panic!("invalid IRQ state");
            }
        }
    }
    ackInterrupt(irq);
}

