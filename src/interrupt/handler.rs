use crate::arch::resetTimer;
use crate::config::{irqInvalid, maxIRQ};
use crate::interrupt::*;
use core::intrinsics::unlikely;
use log::debug;
use sel4_common::structures::exception_t;
use sel4_cspace::interface::CapTag;
use sel4_ipc::notification_t;
use sel4_task::{activateThread, schedule, timerTick};

#[no_mangle]
pub fn handleInterruptEntry() -> exception_t {
    let irq = getActiveIRQ();

    if irq != irqInvalid {
        handleInterrupt(irq);
    } else {
        debug!("Spurious interrupt!");
        debug!("Superior IRQ!! SIP {:#x}\n", read_sip());
    }

    schedule();
    activateThread();
    exception_t::EXCEPTION_NONE
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
    match get_irq_state(irq) {
        IRQState::IRQInactive => {
            debug!("IRQInactive");
            mask_interrupt(true, irq);
            debug!("Received disabled IRQ: {}\n", irq);
        }
        IRQState::IRQSignal => {
            debug!("IRQSignal");
            let handler_slot = get_irq_handler_slot(irq);
            let handler_cap = &handler_slot.cap;
            if handler_cap.get_cap_type() == CapTag::CapNotificationCap
                && handler_cap.get_nf_can_send() != 0
            {
                let nf = convert_to_mut_type_ref::<notification_t>(handler_cap.get_nf_ptr());
                nf.send_signal(handler_cap.get_nf_badge());
            }
        }
        IRQState::IRQTimer => {
            timerTick();
            resetTimer();
        }
        #[cfg(feature = "ENABLE_SMP")]
        IRQState::IRQIPI => {
            unsafe { crate::ffi::handleIPI(irq, true) };
        }
        IRQState::IRQReserved => {
            debug!("Received unhandled reserved IRQ: {}\n", irq);
        }
    }
    ackInterrupt(irq);
}
