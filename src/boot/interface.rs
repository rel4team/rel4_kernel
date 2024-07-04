use sel4_task::{get_idle_thread, set_current_thread, tcb_t};

use super::{
    mm::{avail_p_regs_addr, avail_p_regs_size},
    try_init_kernel,
};

#[no_mangle]
pub fn pRegsToR(ptr: *const usize, size: usize) {
    unsafe {
        avail_p_regs_addr = ptr as usize;
        avail_p_regs_size = size;
        // debug!("{:#x} {:#x}", avail_p_regs_addr, avail_p_regs_size);
    }
}

extern "C" {
    fn ki_boot_end();
}

#[no_mangle]
pub fn rust_try_init_kernel(
    ui_p_reg_start: usize,
    ui_p_reg_end: usize,
    pv_offset: isize,
    v_entry: usize,
    dtb_phys_addr: usize,
    dtb_size: usize,
) -> bool {
    try_init_kernel(
        ui_p_reg_start,
        ui_p_reg_end,
        pv_offset,
        v_entry,
        dtb_phys_addr,
        dtb_size,
        ki_boot_end as usize,
    )
}

#[cfg(feature = "ENABLE_SMP")]
#[no_mangle]
pub fn rust_try_init_kernel_secondary_core(hart_id: usize, core_id: usize) -> bool {
    use super::try_init_kernel_secondary_core;
    try_init_kernel_secondary_core(hart_id, core_id)
}

#[no_mangle]
pub fn tcbSchedEnqueue(tcb: *mut tcb_t) {
    // panic!("should not be invoke!");
    unsafe {
        (*tcb).sched_enqueue();
    }
}

#[no_mangle]
pub fn switchToIdleThread() {
    // panic!("should not be invoke!");
    let _ = get_idle_thread().set_vm_root();
    set_current_thread(get_idle_thread());
}
