pub type pptr_t = usize;
pub type paddr_t = usize;
pub type vptr_t = usize;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct vm_attributes_t {
    pub words: [usize; 1],
}

impl vm_attributes_t {
    pub fn new(value: usize) -> Self {
        Self {
            words: [value & 0x1usize],
        }
    }

    pub fn from_word(w: usize) -> Self {
        Self { words: [w] }
    }

    pub fn get_execute_never(&self) -> usize {
        self.words[0] & 0x1usize
    }

    pub fn set_execute_never(&mut self, v64: usize) {
        self.words[0] &= !0x1usize;
        self.words[0] |= (v64 << 0) & 0x1usize;
    }
}
