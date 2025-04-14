use alloc::sync::Arc;
use lazy_static::lazy_static;

pub static IRQ_ALLOCATOR: IrqAllocator = IrqAllocator::new();

pub struct Bitmap {
    data: u32,
}

impl Bitmap {
    pub const fn new() -> Self {
        Bitmap { data: 0 }
    }

    pub fn set(&mut self, index: usize) {
        if index < 32 {
            self.data |= 1 << index;
        }
    }

    pub fn clear(&mut self, index: usize) {
        if index < 32 {
            self.data &= !(1 << index);
        }
    }

    pub fn get(&self, index: usize) -> bool {
        if index < 32 {
            (self.data & (1 << index)) != 0
        } else {
            false
        }
    }

    pub fn find_first_unset(&self) -> Option<usize> {
        let inverted = !self.data;
        if inverted == 0 {
            None
        } else {
            Some(inverted.trailing_zeros() as usize)
        }
    }
}

pub struct IrqAllocator {
    bitmap: Bitmap,
}

impl IrqAllocator {
    pub const fn new() -> Self {
        let allocator = IrqAllocator {
            bitmap: Bitmap::new(),
        };
        // allocator.bitmap.set(0);
        allocator
    }
    #[inline]
    pub fn alloc(&mut self) -> Option<usize> {
        if let Some(index) = self.bitmap.find_first_unset() {
            self.bitmap.set(index);
            Some(index)
        } else {
            None
        }
    }
    #[inline]
    pub fn free(&mut self, index: usize) {
        if index != 0 {
            self.bitmap.clear(index);
        }
    }
}
