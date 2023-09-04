use task_manager::{tcb_queue_t, tcb_t, ThreadState, set_thread_state};


pub const EPState_Idle: usize = EPState::Idle as usize;
pub const EPState_Send: usize = EPState::Send as usize;
pub const EPState_Recv: usize = EPState::Recv as usize;

#[derive(PartialEq, Eq, Debug)]
pub enum EPState {
    Idle = 0,
    Send = 1,
    Recv = 2,
}

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
    pub fn get_state(&self) -> EPState {
        unsafe {
            core::mem::transmute::<u8, EPState>((self.words[0] & 0x3usize) as u8)
        }
    }

    #[inline]
    pub fn get_queue(&self) -> tcb_queue_t {
        tcb_queue_t { head: self.get_queue_head(), tail: self.get_queue_tail() }
    }

    #[inline]
    pub fn set_queue(&mut self, tcb_queue: &tcb_queue_t) {
        self.set_queue_head(tcb_queue.head);
        self.set_queue_tail(tcb_queue.tail);
    }

    #[inline]
    pub fn cancel_ipc(&mut self, tcb: &mut tcb_t) {
        let mut queue = self.get_queue();
        queue.ep_dequeue(tcb);
        self.set_queue(&queue);
        if queue.head == 0 {
            self.set_state(EPState::Idle as usize);
        }
        set_thread_state(tcb, ThreadState::ThreadStateInactive);
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
        (*ptr).get_state() as usize
    }
}

#[inline]
pub fn ep_ptr_set_queue(epptr: *const endpoint_t, queue: tcb_queue_t) {
    unsafe {
        (*(epptr as *mut endpoint_t)).set_queue(&queue);
    }
}

#[inline]
pub fn ep_ptr_get_queue(epptr: *const endpoint_t) -> tcb_queue_t {
   unsafe {
    (*epptr).get_queue()
   }
}

