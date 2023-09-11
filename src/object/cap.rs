use super::interrupt::intStateIRQNode;
use cspace::interface::*;
use cspace::compatibility::*;
pub fn deletingIRQHandler(irq: usize) {
    unsafe {
        let slot = (intStateIRQNode + irq) as *mut cte_t;
        cteDeleteOne(slot);
    }
}
