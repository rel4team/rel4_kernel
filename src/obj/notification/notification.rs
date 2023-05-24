#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct notification_t {
    pub words: [usize; 4],
}