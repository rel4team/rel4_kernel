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
        Self {
            words: [w]
        }
    }

    pub fn get_execute_never(&self) -> usize {
        self.words[0] & 0x1usize
    }

    pub fn set_execute_never(&mut self, v64: usize) {
        self.words[0] &= !0x1usize;
        self.words[0] |= (v64 << 0) & 0x1usize;
    }
}

#[inline]
pub fn vm_attributes_new(value: usize) -> vm_attributes_t {
    vm_attributes_t {
        words: [value & 0x1usize],
    }
}

#[inline]
#[no_mangle]
pub fn vmAttributesFromWord(w: usize) -> vm_attributes_t {
    let attr = vm_attributes_t { words: [w] };
    attr
}

pub fn vm_attributes_get_riscvExecuteNever(vm_attributes: vm_attributes_t) -> usize {
    let ret = (vm_attributes.words[0] & 0x1usize) >> 0;
    ret
}

pub fn vm_attributes_set_riscvExecuteNever(
    mut vm_attributes: vm_attributes_t,
    v64: usize,
) -> vm_attributes_t {
    vm_attributes.words[0] &= !0x1usize;
    vm_attributes.words[0] |= (v64 << 0) & 0x1usize;
    return vm_attributes;
}