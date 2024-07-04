extern "C" {
    pub fn ksIdleThreadTCB();
    #[cfg(feature = "ENABLE_SMP")]
    pub fn doMaskReschedule(mask: usize);
    pub fn kernel_stack_alloc();
}
