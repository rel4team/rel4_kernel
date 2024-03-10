use core::intrinsics::unlikely;
use crate::common::structures::exception_t;
use crate::cspace::interface::CapTag;
use log::debug;
use riscv::register::scause;
use crate::async_runtime::{coroutine_run_until_blocked, coroutine_wake, NEW_BUFFER_MAP, NewBuffer};
use crate::boot::cpu_idle;
use crate::task_manager::{activateThread, schedule, timerTick};
use crate::task_manager::ipc::notification_t;
use crate::config::{irqInvalid, maxIRQ};
use crate::interrupt::*;
use crate::riscv::resetTimer;


#[no_mangle]
pub fn handleInterruptEntry() -> exception_t {
    let irq = getActiveIRQ();
    let scause = scause::read();
    match scause.cause() {
        scause::Trap::Interrupt(scause::Interrupt::SupervisorExternal) => {
            debug!("SupervisorExternal");
        }
        scause::Trap::Interrupt(scause::Interrupt::UserExternal) => {
            debug!("UserExternal");
        }
        _ => {

        }
    }

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
    unsafe {
        cpu_idle[cpu_id()] = false;
    }
    // debug!("irq: {}", irq);
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
                && handler_cap.get_nf_can_send() != 0 {
                let nf = convert_to_mut_type_ref::<notification_t>(handler_cap.get_nf_ptr());
                nf.send_signal(handler_cap.get_nf_badge());
            } else {
                debug!("no ntfn signal");
            }
        }
        IRQState::IRQTimer => {
            for item in unsafe { &NEW_BUFFER_MAP } {

                let new_buffer = item.buf;
                // debug!("new buffer addr: {:#x}", new_buffer as *const NewBuffer as usize);
                if new_buffer.recv_req_status == true {
                    debug!("wake cid: {}", item.cid.0);
                    coroutine_wake(&item.cid);
                }
            }
            coroutine_run_until_blocked();
            timerTick();
            resetTimer();
        }
        #[cfg(feature = "ENABLE_SMP")]
        IRQState::IRQIPI => {
            unsafe { crate::deps::handleIPI(irq, true) };
        }
        IRQState::IRQReserved => {
            debug!("Received unhandled reserved IRQ: {}\n", irq);
        }
    }
    ackInterrupt(irq);
}
