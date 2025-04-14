use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::AtomicUsize;
use core::task::{Context, Poll};
use crate::async_runtime::{coroutine_get_current, coroutine_get_immediate_value};

#[derive(Copy, Clone)]
pub struct IndexAllocator<const SIZE: usize> where
    [(); (SIZE + 7) / 8]: {
    bitmap: [u8; (SIZE + 7) / 8]
}

impl<const SIZE: usize> IndexAllocator<SIZE> where
    [(); (SIZE + 7) / 8]: {
    pub const fn new() -> Self {
        Self {
            bitmap :[0; (SIZE + 7) / 8]
        }
    }

    pub fn allocate(&mut self) -> Option<usize> {
        (0..SIZE).find(|i| {self.bitmap[i / 8] & (1 << (i % 8)) == 0 }).map(|index| {
            self.bitmap[index / 8] |= 1 << (index % 8);
            index
        })
    }

    pub fn release(&mut self, index: usize) {
        self.bitmap[index / 8] &= !(1 << (index % 8));
    }
}

pub struct BitMap64 {
    data: u64,
}

impl BitMap64 {
    #[inline]
    pub const fn new() -> Self {
        BitMap64 { data: 0 }
    }

    #[inline]
    pub fn set(&mut self, pos: usize) {
        assert!(pos < 64, "Position out of range");
        self.data |= 1 << pos;
    }

    #[inline]
    pub fn full(&self) -> bool {
        self.find_first_zero() == 64
    }

    #[inline]
    pub fn emtpy(&self) -> bool {
        self.find_first_one() == 64
    }

    #[inline]
    pub fn clear(&mut self, pos: usize) {
        assert!(pos < 64, "Position out of range");
        self.data &= !(1 << pos);
    }

    #[inline]
    pub fn find_first_one(&self) -> usize {
        self.data.trailing_zeros() as usize
    }

    #[inline]
    pub fn find_first_zero(&self) -> usize {
        self.data.trailing_ones() as usize
    }
}

pub async fn yield_now() -> Option<u64> {
    let mut helper = Box::new(YieldHelper::new());
    helper.await;
    coroutine_get_immediate_value(&coroutine_get_current())
}

struct YieldHelper(bool);

impl YieldHelper {
    pub fn new() -> Self {
        Self {
            0: false,
        }
    }
}

impl Future for YieldHelper {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.0 == false {
            self.0 = true;
            return Poll::Pending;
        }
        return Poll::Ready(());
    }
}

#[derive(Copy, Clone)]
pub struct RingBuffer<T, const SIZE: usize> {
    data: [T; SIZE],
    pub start: usize,
    pub end: usize,
}

impl<T, const SIZE: usize> RingBuffer<T, SIZE> where T: Default + Copy + Clone {
    pub fn new() -> Self {
        Self {
            data: [T::default(); SIZE],
            start: 0,
            end: 0,
        }
    }

    #[inline]
    pub fn size(&self) -> usize {
        (self.end + SIZE - self.start) % SIZE
    }

    #[inline]
    pub fn empty(&self) -> bool {
        self.end == self.start
    }

    #[inline]
    pub fn full(&self) -> bool {
        (self.end + 1) % SIZE == self.start
    }

    #[inline]
    pub fn push(&mut self, item: &T) -> Result<(), ()> {
        if !self.full() {
            self.data[self.end] = *item;
            self.end = (self.end + 1) % SIZE;
            return Ok(());
        }
        Err(())
    }

    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        return if !self.empty() {
            let ans = self.data[self.start];
            self.start = (self.start + 1) % SIZE;
            Some(ans)
        } else {
            None
        }
    }
}


pub struct SafeRingBuffer<T, const SIZE: usize> {
    data: [T; SIZE],
    pub start: usize,
    pub end: usize,
    pub count: AtomicUsize,
}

impl<T, const SIZE: usize> SafeRingBuffer<T, SIZE> where T: Default + Copy + Clone {
    pub fn new() -> Self {
        Self {
            data: [T::default(); SIZE],
            start: 0,
            end: 0,
            count: AtomicUsize::new(0)
        }
    }

    #[inline]
    pub fn pop_safe(&mut self) -> Option<T> {
        if !(self.count.load(core::sync::atomic::Ordering::Relaxed) == 0) {
            let item = self.data[self.start];
            self.start = (self.start + 1) % SIZE;
            self.count.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
            Some(item)
        } else {
            None
        }
    }

    #[inline]
    pub fn push_safe(&mut self, item: &T) -> Result<(), ()> {
        let _cnt = self.count.load(core::sync::atomic::Ordering::Relaxed);
        // debug_println!("push cnt: {}, SIZE: {}", cnt, SIZE);
        if !(self.count.load(core::sync::atomic::Ordering::SeqCst) == SIZE) {
            // debug_println!("push cnt: {}, SIZE: {}", cnt, SIZE);
            self.data[self.end] = *item;
            self.end = (self.end + 1) % SIZE;
            self.count.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(())
        } else {
            Err(())
        }
    }
}
