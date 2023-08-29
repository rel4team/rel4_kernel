#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct endpoint_t {
    pub words: [usize; 2],
}

impl endpoint_t {
    #[inline]
    pub fn set_queue_head(&mut self, v64: usize) {
        self.words[1] &= !0xffffffffffffffffusize;
        self.words[1] |= (v64 << 0) & 0xffffffffffffffff;
    }

    #[inline]
    pub fn get_queue_head(&self) -> usize {
        let ret = (self.words[1] & 0xffffffffffffffffusize) >> 0;
        ret
    }

    #[inline]
    pub fn set_queue_tail(&mut self, v64: usize) {
        self.words[0] &= !0x7ffffffffcusize;
        self.words[0] |= (v64 << 0) & 0x7ffffffffc;
    }

    #[inline]
    pub fn get_queue_tail(&self) -> usize {
        let mut ret = (self.words[0] & 0x7ffffffffcusize) >> 0;
        if (ret & (1usize << (38))) != 0 {
            ret |= 0xffffff8000000000;
        }
        ret
    }

    #[inline]
    pub fn set_state(&mut self, v64: usize) {
        self.words[0] &= !0x3usize;
        self.words[0] |= (v64 << 0) & 0x3;
    }
    
    #[inline]
    pub fn get_state(&self) -> usize {
        let ret = (self.words[0] & 0x3usize) >> 0;
        ret
    }
}

#[inline]
pub fn endpoint_ptr_set_epQueue_head(ptr: *mut endpoint_t, v64: usize) {
    unsafe {
        (*ptr).set_queue_head(v64)
    }
}

#[inline]
pub fn endpoint_ptr_get_epQueue_head(ptr: *const endpoint_t) -> usize {
    unsafe {
        (*ptr).get_queue_head()
    }
}

#[inline]
pub fn endpoint_ptr_set_epQueue_tail(ptr: *mut endpoint_t, v64: usize) {
    unsafe {
        (*ptr).set_queue_tail(v64)
    }
}

#[inline]
pub fn endpoint_ptr_get_epQueue_tail(ptr: *const endpoint_t) -> usize {
    unsafe {
        (*ptr).get_queue_tail()
    }
}

#[inline]
pub fn endpoint_ptr_set_state(ptr: *mut endpoint_t, v64: usize) {
    unsafe {
        (*ptr).set_state(v64)
    }
}

#[inline]
pub fn endpoint_ptr_get_state(ptr: *const endpoint_t) -> usize {
    unsafe {
        (*ptr).get_state()
    }
}
