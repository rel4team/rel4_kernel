//! SBI (RISC-V Supervisor Binary Interface) wrapper
#![allow(unused)]

mod arch_tcb;
mod registers;
pub use arch_tcb::ArchTCB;
pub use registers::*;
use riscv::register::time;

const SBI_SET_TIMER: usize = 0;
const SBI_CONSOLE_PUTCHAR: usize = 1;
const SBI_CONSOLE_GETCHAR: usize = 2;

const SBI_CLEAR_IPI: usize = 3;
const SBI_REMOTE_SFENCE_VMA: usize = 6;
const SBI_SHUTDOWN: usize = 8;
const SYSCALL_WRITE: usize = 64;

#[no_mangle]
pub fn sbi_call(which: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret;
    unsafe {
        core::arch::asm!(
        "ecall",
        inlateout("x10") arg0 => ret,
        in("x11") arg1,
        in("x12") arg2,
        in("x17") which,
        );
    }
    ret
}

pub fn set_timer(timer: usize) {
    sbi_call(SBI_SET_TIMER, timer, 0, 0);
}

pub fn console_putchar(c: usize) {
    sbi_call(SBI_CONSOLE_PUTCHAR, c, 0, 0);
}

pub fn console_getchar() -> usize {
    sbi_call(SBI_CONSOLE_GETCHAR, 0, 0, 0)
}

pub fn clear_ipi() {
    sbi_call(SBI_CLEAR_IPI, 0, 0, 0);
}
pub fn shutdown() -> ! {
    sbi_call(SBI_SHUTDOWN, 0, 0, 0);
    panic!("It should shutdown!");
}

pub fn sys_write(fd: usize, buffer: &[u8]) {
    sbi_call(SYSCALL_WRITE, fd, buffer.as_ptr() as usize, buffer.len());
}

pub fn remote_sfence_vma(hart_mask: usize, start: usize, size: usize) {
    let virt_addr_hart_mask = (&hart_mask) as *const usize as usize;
    sbi_call(SBI_REMOTE_SFENCE_VMA, virt_addr_hart_mask, 0, 0);
}

pub fn get_time() -> usize {
    time::read()
}
