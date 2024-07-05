extern "C" {
    pub fn kernel_stack_alloc();
}

#[cfg(feature = "ENABLE_SMP")]
/// This function is used to map the core.
extern "C" {
    pub fn coreMap();
}
