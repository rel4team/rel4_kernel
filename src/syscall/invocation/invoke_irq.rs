

use common::structures::exception_t;
use cspace::interface::{cte_t, cte_insert, cap_t};

use crate::interrupt::{set_irq_state, IRQState};

pub fn invoke_irq_control(irq: usize, handler_slot: &mut cte_t, control_slot: &mut cte_t) -> exception_t {
    set_irq_state(IRQState::IRQSignal, irq);
    cte_insert(&cap_t::new_irq_handler_cap(irq), control_slot, handler_slot);
    exception_t::EXCEPTION_NONE
}