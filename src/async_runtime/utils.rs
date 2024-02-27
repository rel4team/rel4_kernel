use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use crate::async_runtime::{coroutine_get_current, coroutine_get_immediate_value};

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
