use crate::{
    config::CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION, object::interrupt::isIRQPending,
    structures::exception_t,
};

use super::boot::ksWorkUnitsCompleted;

#[no_mangle]
pub fn preemptionPoint() -> exception_t {
    unsafe {
        ksWorkUnitsCompleted += 1;
        if ksWorkUnitsCompleted >= CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION {
            ksWorkUnitsCompleted = 0;

            if isIRQPending() {
                return exception_t::EXCEPTION_PREEMTED;
            }
        }
        exception_t::EXCEPTION_NONE
    }
}
