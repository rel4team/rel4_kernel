use core::arch::asm;

pub fn read_stval()->usize{
    let temp:usize;
    unsafe{
        asm!("csrr {}, stval",out(reg)temp);
    }
    temp
}

pub extern "C" fn write_stvec(val: usize) {
    unsafe {
        asm!("csrw stvec , {}",in(reg) val);
    }
}