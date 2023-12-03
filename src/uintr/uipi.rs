pub unsafe fn uipi_send(index: usize) {
    core::arch::asm!(".insn i 0b1111011, 0b010, x0, {}, 0x0", in(reg) index);
}

pub unsafe fn uipi_read() -> usize {
    let mut ret: usize = 0;
    core::arch::asm!(".insn i 0b1111011, 0b010, {}, x0, 0x1", out(reg) ret);
    ret
}

pub unsafe fn uipi_write(bits: usize) {
    core::arch::asm!(".insn i 0b1111011, 0b010, x0, {}, 0x2", in(reg) bits);
}

pub unsafe fn uipi_activate() {
    core::arch::asm!(".insn i 0b1111011, 0b010, x0, x0, 0x3");
}

pub unsafe fn uipi_deactivate() {
    core::arch::asm!(".insn i 0b1111011, 0b010, x0, x0, 0x4");
}