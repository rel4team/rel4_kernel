use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use buddy_system_allocator::Heap;
use spin::mutex::Mutex;

const HEAP_SIZE: usize = 1 << 20;
pub static mut HEAP: spin::Mutex<Heap> = Mutex::new(Heap::empty());

static mut HEAP_MEM: [u64; HEAP_SIZE / 8] = [0u64; HEAP_SIZE / 8];

pub fn init_heap() {
    unsafe {
        HEAP.lock().init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE);
    }
}

struct Global;
#[global_allocator]
static GLOBAL: Global = Global;

unsafe impl GlobalAlloc for Global {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        return HEAP.lock().alloc(layout).ok()
            .map_or(0 as *mut u8, |allocation| allocation.as_ptr());
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        HEAP.lock().dealloc(NonNull::new_unchecked(ptr), layout);
        return;
    }
}