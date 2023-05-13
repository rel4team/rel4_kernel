use super::{mm::{avail_p_regs_addr, avail_p_regs_size}, try_init_kernel};

#[no_mangle]
pub fn pRegsToR(ptr: *const usize, size: usize) {
    unsafe {
        avail_p_regs_addr = ptr as usize;
        avail_p_regs_size = size;
        // println!("{:#x} {:#x}", avail_p_regs_addr, avail_p_regs_size);
    }
}

extern "C" {
    fn ki_boot_end();
}

#[no_mangle]
pub fn rust_try_init_kernel(ui_p_reg_start: usize,
    ui_p_reg_end: usize,
    pv_offset: isize,
    v_entry: usize,
    dtb_phys_addr: usize,
    dtb_size: usize) -> bool {

    try_init_kernel(ui_p_reg_start, ui_p_reg_end, pv_offset, v_entry, dtb_phys_addr, dtb_size, ki_boot_end as usize)
}