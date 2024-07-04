use sel4_common::structures::exception_t;
use sel4_cspace::interface::{cap_t, cte_insert, cte_t};

use crate::interrupt::{get_irq_handler_slot, set_irq_state, IRQState};

pub fn invoke_irq_control(
    irq: usize,
    handler_slot: &mut cte_t,
    control_slot: &mut cte_t,
) -> exception_t {
    set_irq_state(IRQState::IRQSignal, irq);
    cte_insert(&cap_t::new_irq_handler_cap(irq), control_slot, handler_slot);
    exception_t::EXCEPTION_NONE
}

#[inline]
pub fn invoke_set_irq_handler(irq: usize, cap: &cap_t, slot: &mut cte_t) {
    let irq_slot = get_irq_handler_slot(irq);
    irq_slot.delete_one();
    cte_insert(cap, slot, irq_slot);
}

#[inline]
pub fn invoke_clear_irq_handler(irq: usize) {
    get_irq_handler_slot(irq).delete_one();
}
