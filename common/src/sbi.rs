#![allow(unused)]

use riscv::register::time;

const SBI_SET_TIMER: usize = 0;
const SBI_CONSOLE_PUTCHAR: usize = 1;
const SBI_CONSOLE_GETCHAR: usize = 2;
const SBI_SHUTDOWN: usize = 8;
const SYSCALL_WRITE:usize =64;

#[linkage = "weak"]
#[no_mangle]
pub fn sbi_call(which: usize, arg0: usize, arg1: usize, arg2: usize) -> usize {
    panic!("Cannot find sbi_call!")
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

pub fn shutdown() -> ! {
    sbi_call(SBI_SHUTDOWN, 0, 0, 0);
    panic!("It should shutdown!");
}

pub fn sys_write(fd: usize, buffer: &[u8]){
    sbi_call(SYSCALL_WRITE, fd, buffer.as_ptr() as usize, buffer.len());
}

pub fn get_time() -> usize {
    time::read()
}
