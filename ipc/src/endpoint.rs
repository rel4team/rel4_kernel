use common::{utils::{convert_to_mut_type_ref, convert_to_option_mut_type_ref}, plus_define_bitfield};
use task_manager::{tcb_queue_t, tcb_t, ThreadState, set_thread_state, rescheduleRequired, schedule_tcb, possible_switch_to};
use vspace::pptr_t;

use crate::transfer::do_ipc_transfer;


pub const EPState_Idle: usize = EPState::Idle as usize;
pub const EPState_Send: usize = EPState::Send as usize;
pub const EPState_Recv: usize = EPState::Recv as usize;

#[derive(PartialEq, Eq, Debug)]
pub enum EPState {
    Idle = 0,
    Send = 1,
    Recv = 2,
}

plus_define_bitfield! {
    endpoint_t, 2, 0, 0, 0 => {
        new, 0 => {
            queue_head, get_queue_head, set_queue_head, 1, 0, 64, 0, false,
            queue_tail, get_queue_tail, set_queue_tail, 0, 2, 37, 2, true,
            state, get_usize_state, set_state, 0, 0, 2, 0, false
        }
    }
}

impl endpoint_t {
    #[inline]
    pub fn get_ptr(&self) -> pptr_t {
        self as *const Self as pptr_t
    }

    #[inline]
    pub fn get_state(&self) -> EPState {
        unsafe {
            core::mem::transmute::<u8, EPState>(self.get_usize_state() as u8)
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

    #[inline]
    pub fn cancel_all_ipc(&mut self) {
        match self.get_state() {
            EPState::Idle => {}
            _ => {
                let mut op_thread = convert_to_option_mut_type_ref::<tcb_t>(self.get_queue_head());
                self.set_state(EPState::Idle as usize);
                self.set_queue_head(0);
                self.set_queue_tail(0);
                while let Some(thread) = op_thread {
                    set_thread_state(thread, ThreadState::ThreadStateRestart);
                    thread.sched_enqueue();
                    op_thread = convert_to_option_mut_type_ref::<tcb_t>(thread.tcbEPNext);
                }
                rescheduleRequired();
            }
        }
    }

    pub fn cancel_badged_sends(&mut self, badge: usize) {
        match self.get_state() {
            EPState::Idle | EPState::Recv => {}
            EPState::Send => {
                let mut queue = self.get_queue();
                self.set_state(EPState::Idle as usize);
                self.set_queue_head(0);
                self.set_queue_tail(0);
                let mut thread_ptr = queue.head;
                while thread_ptr != 0 {
                    let thread = convert_to_mut_type_ref::<tcb_t>(thread_ptr);
                    thread_ptr = thread.tcbEPNext;
                    if thread.tcbState.get_blocking_ipc_badge() == badge {
                        set_thread_state(thread, ThreadState::ThreadStateRestart);
                        thread.sched_enqueue();
                        queue.ep_dequeue(thread);
                    }
                }
                self.set_queue(&queue);
                if queue.head != 0 {
                    self.set_state(EPState::Send as usize);
                }
                rescheduleRequired();
            }
        }
    }

    pub fn send_ipc(&mut self, blocking: bool, src_thread: &mut tcb_t,
        do_call: bool, can_grant: bool, badge: usize, can_grant_reply: bool) {
        match self.get_state() {
            EPState::Idle | EPState::Send => {
                if blocking {
                    src_thread.tcbState.set_ts_type(ThreadState::ThreadStateBlockedOnSend as usize);
                    src_thread.tcbState.set_blocking_object(self.get_ptr());
                    src_thread.tcbState.set_blocking_ipc_can_grant(can_grant as usize);
                    src_thread.tcbState.set_blocking_ipc_badge(badge);
                    src_thread.tcbState.set_blocking_ipc_can_grant_reply(can_grant_reply as usize);
                    src_thread.tcbState.set_blocking_ipc_is_call(do_call as usize);
                    schedule_tcb(src_thread);

                    let mut queue = self.get_queue();
                    queue.ep_append(src_thread);
                    self.set_state(EPState::Send as usize);
                    self.set_queue(&queue);
                }
            }

            EPState::Recv => {
                let mut queue = self.get_queue();
                let op_dest_thread = convert_to_option_mut_type_ref::<tcb_t>(queue.head);
                assert!(op_dest_thread.is_some());
                let dest_thread = op_dest_thread.unwrap();
                queue.ep_dequeue(dest_thread);
                self.set_queue(&queue);
                if queue.empty() {
                    self.set_state(EPState::Idle as usize);
                }
                // TOOD
                do_ipc_transfer(src_thread, Some(&self), badge, can_grant, dest_thread);
                let reply_can_grant = dest_thread.tcbState.get_blocking_ipc_can_grant() != 0;
                set_thread_state(dest_thread, ThreadState::ThreadStateRunning);
                possible_switch_to(dest_thread);
                if do_call {
                    if can_grant || can_grant_reply {
                        dest_thread.setup_caller_cap(src_thread, reply_can_grant);
                    } else {
                        set_thread_state(src_thread, ThreadState::ThreadStateInactive);
                    }
                }
            }
        }
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