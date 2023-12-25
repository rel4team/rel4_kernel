use log::debug;
use crate::common::utils::{convert_to_mut_type_ref, convert_to_option_mut_type_ref};
use crate::plus_define_bitfield;
use super::super::{tcb_t, tcb_queue_t, set_thread_state, possible_switch_to, ThreadState, rescheduleRequired};
use super::super::registers::*;

#[derive(PartialEq, Eq)]
pub enum NtfnState {
    Idle = 0,
    Waiting = 1,
    Active = 2,
}

pub const NtfnState_Idle: usize = NtfnState::Idle as usize;
pub const NtfnState_Waiting: usize = NtfnState::Waiting as usize;
pub const NtfnState_Active: usize = NtfnState::Active as usize;

plus_define_bitfield! {
    notification_t, 5, 0, 0, 0 => {
        new, 0 => {
            bound_tcb, get_bound_tcb, set_bound_tcb, 3, 0, 39, 0, true,
            msg_identifier, get_msg_identifier, set_msg_identifier, 2, 0, 64, 0, false,
            queue_head, get_queue_head, set_queue_head, 1, 0, 39, 0, true,
            queue_tail, get_queue_tail, set_queue_tail, 0, 25, 39, 0, true,
            state, get_usize_state, set_state, 0, 0, 2, 0, false,
            uintr_flag, get_uintr_flag, set_uintr_flag, 4, 9, 1, 0, false,
            recv_idx, get_recv_idx, set_recv_idx, 4, 0, 9, 0, false
        }
    }
}

impl notification_t {
    #[inline]
    pub fn get_state(&self) -> NtfnState {
        unsafe {
            core::mem::transmute::<u8, NtfnState>(self.get_usize_state() as u8)
        }
    }

    #[inline]
    pub fn get_queue(&self) -> tcb_queue_t {
        tcb_queue_t { head: self.get_queue_head(), tail: self.get_queue_tail() }
    }

    #[inline]
    pub fn set_queue(&mut self, queue: &tcb_queue_t) {
        self.set_queue_head(queue.head as usize);
        self.set_queue_tail(queue.tail as usize);
    }

    #[inline]
    pub fn active(&mut self, badge: usize) {
        self.set_state(NtfnState::Active as usize);
        self.set_msg_identifier(badge);
    }

    #[inline]
    pub fn cancel_signal(&mut self, tcb: &mut tcb_t) {
        let mut queue = self.get_queue();
        queue.ep_dequeue_tcb(tcb);
        self.set_queue(&queue);
        if queue.head == 0 {
            self.set_state(NtfnState::Idle as usize);
        }
        set_thread_state(tcb, ThreadState::ThreadStateInactive);
    }

    #[inline]
    pub fn cacncel_all_signal(&mut self) {
        if self.get_state() ==  NtfnState::Waiting {
            let mut op_thread = convert_to_option_mut_type_ref::<tcb_t>(self.get_queue_head());
            self.set_state(NtfnState::Idle as usize);
            self.set_queue_head(0);
            self.set_queue_tail(0);
            while let Some(thread) =  op_thread {
                set_thread_state(thread, ThreadState::ThreadStateRestart);
                thread.sched_enqueue();
                op_thread = convert_to_option_mut_type_ref::<tcb_t>(thread.tcbEPNext);
            }
            rescheduleRequired();
        }
    }

    #[inline]
    pub fn bind_tcb(&mut self, tcb: &mut tcb_t) {
        self.set_bound_tcb(tcb.get_ptr());
    }

    #[inline]
    pub fn unbind_tcb(&mut self) {
        self.set_bound_tcb(0);
    }

    #[inline]
    pub fn safe_unbind_tcb(&mut self) {
        let tcb = self.get_bound_tcb();
        self.unbind_tcb();
        if tcb as usize != 0 {
            convert_to_mut_type_ref::<tcb_t>(tcb).unbind_notification();
        }
    }

    #[inline]
    pub fn get_ptr(&self) -> usize {
        self as *const notification_t as usize
    }

    #[inline]
    pub fn send_signal(&mut self, badge: usize) {
        match self.get_state() {
            NtfnState::Idle => {
                if let Some(tcb) = convert_to_option_mut_type_ref::<tcb_t>(self.get_bound_tcb()) {
                    if tcb.get_state() == ThreadState::ThreadStateBlockedOnReceive{
                        tcb.cancel_ipc();
                        set_thread_state(tcb, ThreadState::ThreadStateRunning);
                        tcb.set_register(badgeRegister, badge);
                        possible_switch_to(tcb);
                    } else {
                        self.active(badge);
                    }
                } else {
                    self.active(badge);
                }
            }
            NtfnState::Waiting => {
                let mut queue = self.get_queue();
                if let Some(dest) = convert_to_option_mut_type_ref::<tcb_t>(queue.head) {
                    queue.ep_dequeue_tcb(dest);
                    self.set_queue(&queue);
                    if queue.empty() {
                        self.set_state(NtfnState::Idle as usize);
                    }
                    set_thread_state(dest, ThreadState::ThreadStateRunning);
                    dest.set_register(badgeRegister, badge);
                    possible_switch_to(dest);
                } else {
                    panic!("queue is empty!")
                }
            }
            NtfnState::Active => {
                let mut badge2 = self.get_msg_identifier();
                badge2 |= badge;
                self.set_msg_identifier(badge2);
            }
        }
    }

    pub fn receive_signal(&mut self, recv_thread: &mut tcb_t, is_blocking: bool) {
        match self.get_state() {
            NtfnState::Idle | NtfnState::Waiting => {
                if is_blocking {
                    recv_thread.tcbState.set_blocking_object(self.get_ptr());
                    set_thread_state(recv_thread, ThreadState::ThreadStateBlockedOnNotification);
                    let mut queue = self.get_queue();
                    queue.ep_append_tcb(recv_thread);
                    self.set_state(NtfnState::Waiting as usize);
                    self.set_queue(&queue);
                } else {
                    recv_thread.set_register(badgeRegister, 0);
                }
            }

            NtfnState::Active => {
                recv_thread.set_register(badgeRegister, self.get_msg_identifier());
                self.set_state(NtfnState::Idle as usize);
            }
        }
    }
}

#[inline]
pub fn notification_ptr_get_ntfnBoundTCB(notification_ptr: *const notification_t) -> usize {
    unsafe {
        (*notification_ptr).get_bound_tcb()
    }
}

#[inline]
pub fn notification_ptr_get_state(notification_ptr: *const notification_t) -> usize {
    unsafe {
        (*notification_ptr).get_state() as usize
    }
}