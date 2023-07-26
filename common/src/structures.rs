#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum exception_t {
    EXCEPTION_NONE,
    EXCEPTION_FAULT,
    EXCEPTION_LOOKUP_FAULT,
    EXCEPTION_SYSCALL_ERROR,
    EXCEPTION_PREEMTED,
    padding = isize::MAX - 1,
}
