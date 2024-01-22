use core::intrinsics::{likely, unlikely};

use crate::MASK;
use crate::common::fault::*;
use crate::common::message_info::seL4_MessageInfo_t;
use crate::common::utils::{pageBitsForSize, convert_to_mut_type_ref};
use crate::cspace::interface::{cte_t, resolve_address_bits, CapTag, cap_t, mdb_node_t, cte_insert};
use crate::vspace::{set_vm_root, pptr_t, VMReadWrite, VMReadOnly};

use crate::common::sel4_config::*;
use crate::common::structures::{seL4_IPCBuffer, exception_t};
use super::registers::{
    SSTATUS, n_msgRegisters, msgRegister, msgInfoRegister,
    n_syscallMessage, n_exceptionMessage, fault_messages, n_contextRegisters
};

use super::scheduler::{possible_switch_to, schedule_tcb};
use super::structures::lookupSlot_raw_ret_t;

use super::{ready_queues_index, addToBitmap, removeFromBitmap, NextIP, FaultIP, rescheduleRequired, tcb_queue_t, set_current_thread, get_currenct_thread};

use super::thread_state::*;


#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct arch_tcb_t {
    pub registers: [usize; n_contextRegisters],
}

impl Default for arch_tcb_t {
    fn default() -> Self {
        let mut registers = [0; n_contextRegisters];
        registers[SSTATUS] = 0x00040020;
        Self {registers }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct tcb_t {
    pub tcbArch: arch_tcb_t,
    pub tcbState: thread_state_t,
    pub tcbBoundNotification: usize,
    pub tcbFault: seL4_Fault_t,
    pub tcbLookupFailure: lookup_fault_t,
    pub domain: usize,
    pub tcbMCP: usize,
    pub tcbPriority: usize,
    pub tcbTimeSlice: usize,
    pub tcbFaultHandler: usize,
    pub tcbIPCBuffer: usize,
    #[cfg(feature = "ENABLE_SMP")]
    pub tcbAffinity: usize,
    pub tcbSchedNext: usize,
    pub tcbSchedPrev: usize,
    pub tcbEPNext: usize,
    pub tcbEPPrev: usize,
    #[cfg(feature = "ENABLE_UINTC")]
    pub uintr_inner: uintr_tcb_inner,
}

#[cfg(feature = "ENABLE_UINTC")]
#[derive(Copy, Clone, Debug)]
pub struct uintr_tcb_inner {
    pub uepc: usize,
    pub utvec: usize,
    pub uscratch: usize,
    pub uist: Option<usize>,
}

impl tcb_t {
    #[inline]
    pub fn get_cspace(&self, i: usize) -> &'static cte_t {
        unsafe {
            let p = ((self.get_ptr()) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &*(p.add(i))
        }
    }

    #[inline]
    pub fn init(&mut self) {
        self.tcbArch = arch_tcb_t::default();
    }

    #[inline]
    pub fn get_cspace_mut_ref(&mut self, i: usize) -> &'static mut cte_t {
        unsafe {
            let p = ((self as *mut tcb_t as usize) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &mut *(p.add(i))
        }
    }

    #[inline]
    pub fn get_state(&self) -> ThreadState {
        unsafe { core::mem::transmute::<u8, ThreadState>(self.tcbState.get_ts_type() as u8) }
    }

    #[inline]
    pub fn is_stopped(&self) -> bool {
        match self.get_state() {
            ThreadState::ThreadStateInactive | ThreadState::ThreadStateBlockedOnNotification | ThreadState::ThreadStateBlockedOnReceive
            | ThreadState::ThreadStateBlockedOnReply | ThreadState::ThreadStateBlockedOnSend => true,

            _ => false
        }
    }

    #[inline]
    pub fn is_runnable(&self) -> bool {
        match self.get_state() {
            ThreadState::ThreadStateRunning | ThreadState::ThreadStateRestart   => true,
            _                                                                   => false,
        }
    }

    #[inline]
    pub fn is_current(&self) -> bool {
        self.get_ptr() == get_currenct_thread().get_ptr()
    }

    #[inline]
    pub fn set_register(&mut self, reg: usize, w: usize) {
        self.tcbArch.registers[reg] = w;
    }

    #[inline]
    pub fn get_register(&self, reg: usize) -> usize {
        self.tcbArch.registers[reg]
    }
    
    #[inline]
    pub fn set_mcp_priority(&mut self, mcp: usize) {
        self.tcbMCP = mcp;
    }

    #[inline]
    pub fn set_priority(&mut self, priority: usize) {
        self.sched_dequeue();
        self.tcbPriority = priority;
        if self.is_runnable() {
            if self.is_current() {
                rescheduleRequired();
            } else {
                possible_switch_to(self)
            }
        }
    }

    #[inline]
    pub fn bind_notification(&mut self, addr: pptr_t) {
        self.tcbBoundNotification = addr;
    }

    #[inline]
    pub fn unbind_notification(&mut self) {
        self.tcbBoundNotification = 0;
    }

    #[inline]
    pub fn set_domain(&mut self, dom: usize) {
        self.sched_dequeue();
        self.domain = dom;
        if self.is_runnable() {
            self.sched_enqueue();
        }

        if self.is_current() {
            rescheduleRequired();
        }
    }

    pub fn sched_enqueue(&mut self) {
        let self_ptr = self as *mut tcb_t;
        if self.tcbState.get_tcb_queued() == 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let queue = self.get_sched_queue(idx);
            if queue.tail == 0 {
                queue.head = self_ptr as usize;
                addToBitmap(self.get_cpu(), dom, prio);
            } else {
                convert_to_mut_type_ref::<tcb_t>(queue.tail).tcbSchedNext = self_ptr as usize;
            }
            self.tcbSchedPrev = queue.tail;
            self.tcbSchedNext = 0;
            queue.tail = self_ptr as usize;
            self.tcbState.set_tcb_queued(1);
        }

        #[cfg(feature = "ENABLE_SMP")]
        self.update_queue();
    }

    #[inline]
    pub fn get_sched_queue(&mut self, index: usize) ->  &'static mut tcb_queue_t {
        unsafe {
            #[cfg(feature = "ENABLE_SMP")] {
                use super::ksSMP;
                &mut ksSMP[self.tcbAffinity].ksReadyQueues[index]
            }
            #[cfg(not(feature = "ENABLE_SMP"))] {
                use super::ksReadyQueues;
                &mut ksReadyQueues[index]
            }
        }
    }

    #[inline]
    pub fn get_cpu(&self) -> usize {
        #[cfg(feature = "ENABLE_SMP")] {
            self.tcbAffinity
        }
        #[cfg(not(feature = "ENABLE_SMP"))] {
            0
        }
    }

    pub fn sched_dequeue(&mut self) {
        if self.tcbState.get_tcb_queued() != 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let queue = self.get_sched_queue(idx);
            if self.tcbSchedPrev != 0 {
                convert_to_mut_type_ref::<tcb_t>(self.tcbSchedPrev).tcbSchedNext = self.tcbSchedNext;
            } else {
                queue.head = self.tcbSchedNext as *mut tcb_t as usize;
                if likely(self.tcbSchedNext == 0) {
                    removeFromBitmap(self.get_cpu(), dom, prio);
                }
            }
            if self.tcbSchedNext != 0 {
                convert_to_mut_type_ref::<tcb_t>(self.tcbSchedNext).tcbSchedPrev = self.tcbSchedPrev;
            } else {
                queue.tail = self.tcbSchedPrev as *mut tcb_t as usize;
            }
            // unsafe { ksReadyQueues[idx] = queue; }
            self.tcbState.set_tcb_queued(0);
        }
    }

    pub fn sched_append(&mut self) {
        let self_ptr = self as *mut tcb_t;
        if self.tcbState.get_tcb_queued() == 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let queue = self.get_sched_queue(idx);

            if queue.head == 0 {
                queue.head = self_ptr as usize;
                addToBitmap(self.get_cpu(), dom, prio);
            } else {
                let next = queue.tail;
                // unsafe { (*next).tcbSchedNext = self_ptr as usize };
                convert_to_mut_type_ref::<tcb_t>(next).tcbSchedNext = self_ptr as usize;
            }
            self.tcbSchedPrev = queue.tail;
            self.tcbSchedNext = 0;
            queue.tail = self_ptr as usize;
            // unsafe { ksReadyQueues[idx] = queue; }

            self.tcbState.set_tcb_queued(1);
        }
        #[cfg(feature = "ENABLE_SMP")]
        self.update_queue();
    }

    #[cfg(feature = "ENABLE_SMP")]
    #[inline]
    fn update_queue(&self) {
        use super::{ksSMP, ksCurDomain};
        use crate::common::utils::{cpu_id, convert_to_type_ref};
        use crate::BIT;
        unsafe {
            if self.tcbAffinity != cpu_id() && self.domain == ksCurDomain {
                let target_current = convert_to_type_ref::<tcb_t>(ksSMP[self.tcbAffinity].ksCurThread);
                if ksSMP[self.tcbAffinity].ksIdleThread == ksSMP[self.tcbAffinity].ksCurThread || self.tcbPriority > target_current.tcbPriority {
                    ksSMP[cpu_id()].ipiReschedulePending |= BIT!(self.tcbAffinity);
                }
            }
        }
    }


    pub fn set_vm_root(&self) -> Result<(), lookup_fault_t> {
        // let threadRoot = &(*getCSpace(thread as usize, tcbVTable)).cap;
        let thread_root = self.get_cspace(tcbVTable).cap;
        set_vm_root(&thread_root)
    }

    #[inline]
    pub fn switch_to_this(&mut self) {
        // if hart_id() == 0 {
        //     debug!("switch_to_this: {:#x}", self.get_ptr());
        // }
        // let _unused = self.set_vm_root();
        self.sched_dequeue();
        set_current_thread(self);
    }

    #[inline]
    pub fn get_ptr(&self) -> pptr_t {
        self as *const tcb_t as usize
    }

    #[inline]
    pub fn lookup_slot(&self, cap_ptr: usize) -> lookupSlot_raw_ret_t {
        let thread_root = self.get_cspace(tcbCTable).cap;
        let res_ret = resolve_address_bits(&thread_root, cap_ptr, wordBits);
        lookupSlot_raw_ret_t { status: res_ret.status, slot: res_ret.slot }
    }

    #[inline]
    pub fn setup_reply_master(&mut self) {
        let slot = self.get_cspace_mut_ref(tcbReply);
        if slot.cap.get_cap_type() == CapTag::CapNullCap {
            slot.cap = cap_t::new_reply_cap(1, 1, self.get_ptr());
            slot.cteMDBNode = mdb_node_t::new(0, 1, 1, 0);
        }
    }

    #[inline]
    pub fn suspend(&mut self) {
        if self.get_state() == ThreadState::ThreadStateRunning {
            self.set_register(FaultIP, self.get_register(NextIP));
        }
        // setThreadState(self as *mut Self, ThreadStateInactive);
        set_thread_state(self, ThreadState::ThreadStateInactive);
        self.sched_dequeue();
    }

    #[inline]
    pub fn restart(&mut self) {
        if self.is_stopped() {
            self.setup_reply_master();
            // setThreadState(self as *mut Self, ThreadStateRestart);
            set_thread_state(self, ThreadState::ThreadStateRestart);
            self.sched_enqueue();
            possible_switch_to(self);
        }
    }

    #[inline]
    pub fn setup_caller_cap(&mut self, sender: &mut Self, can_grant: bool) {
        set_thread_state(sender, ThreadState::ThreadStateBlockedOnReply);
        let reply_slot = sender.get_cspace_mut_ref(tcbReply);
        let master_cap = reply_slot.cap;

        assert_eq!(master_cap.get_cap_type(), CapTag::CapReplyCap);
        assert_eq!(master_cap.get_reply_master(), 1);
        assert_eq!(master_cap.get_reply_can_grant(), 1);
        assert_eq!(master_cap.get_reply_tcb_ptr(), sender.get_ptr());

        let caller_slot = self.get_cspace_mut_ref(tcbCaller);
        assert_eq!(caller_slot.cap.get_cap_type(), CapTag::CapNullCap);
        cte_insert(&cap_t::new_reply_cap(can_grant as usize, 0, sender.get_ptr()),
            reply_slot, caller_slot);
    }

    #[inline]
    pub fn delete_caller_cap(&mut self) {
        let caller_slot = self.get_cspace_mut_ref(tcbCaller);
        caller_slot.delete_one();
    }

    pub fn lookup_ipc_buffer(&self, is_receiver: bool) -> Option<&'static seL4_IPCBuffer> {
        let w_buffer_ptr = self.tcbIPCBuffer;
        let buffer_cap = self.get_cspace(tcbBuffer).cap;
        if unlikely(buffer_cap.get_cap_type() != CapTag::CapFrameCap) {
            return None;
        }

        if unlikely(buffer_cap.get_frame_is_device() != 0) {
            return None;
        }

        let vm_rights = buffer_cap.get_frame_vm_rights();
        if likely(vm_rights == VMReadWrite || (!is_receiver && vm_rights == VMReadOnly)) {
            let base_ptr = buffer_cap.get_frame_base_ptr();
            let page_bits = pageBitsForSize(buffer_cap.get_frame_size());
            return Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(base_ptr + (w_buffer_ptr & MASK!(page_bits))));
        }
        return None;
    }

    pub fn lookup_extra_caps(&self, res: &mut [pptr_t; seL4_MsgMaxExtraCaps]) -> Result<(), seL4_Fault_t>{
        let info = seL4_MessageInfo_t::from_word_security(self.get_register(msgInfoRegister));
        if let Some(buffer) = self.lookup_ipc_buffer(false) {
            let length = info.get_extra_caps();
            let mut i = 0;
            while i < length {
                let cptr = buffer.get_extra_cptr(i);
                let lu_ret = self.lookup_slot(cptr);
                if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE)  {
                    return Err(seL4_Fault_t::new_cap_fault(cptr, false as usize));
                }
                res[i] = lu_ret.slot as usize;
                i += 1;
            }
            if i < seL4_MsgMaxExtraCaps {
                res[i] = 0;
            }
        }
        Ok(())
    }

    pub fn lookup_extra_caps_with_buf(&self, res: &mut [pptr_t; seL4_MsgMaxExtraCaps], buf: Option<&seL4_IPCBuffer>) -> Result<(), seL4_Fault_t>{
        let info = seL4_MessageInfo_t::from_word_security(self.get_register(msgInfoRegister));
        if let Some(buffer) = buf {
            let length = info.get_extra_caps();
            let mut i = 0;
            while i < length {
                let cptr = buffer.get_extra_cptr(i);
                let lu_ret = self.lookup_slot(cptr);
                if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE)  {
                    return Err(seL4_Fault_t::new_cap_fault(cptr, false as usize));
                }
                res[i] = lu_ret.slot as usize;
                i += 1;
            }
            if i < seL4_MsgMaxExtraCaps {
                res[i] = 0;
            }
        }
        Ok(())
    }

    pub fn lookup_mut_ipc_buffer(&mut self, is_receiver: bool) -> Option<&'static mut seL4_IPCBuffer> {
        let w_buffer_ptr = self.tcbIPCBuffer;
        let buffer_cap = self.get_cspace(tcbBuffer).cap;
        if buffer_cap.get_cap_type() != CapTag::CapFrameCap {
            return None;
        }

        let vm_rights = buffer_cap.get_frame_vm_rights();
        if vm_rights == VMReadWrite || (!is_receiver && vm_rights == VMReadOnly) {
            let base_ptr = buffer_cap.get_frame_base_ptr();
            let page_bits = pageBitsForSize(buffer_cap.get_frame_size());
            return Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(base_ptr + (w_buffer_ptr & MASK!(page_bits))));
        }
        return None;
    }

    #[inline]
    pub fn set_mr(&mut self, offset: usize, reg: usize) -> usize {
        if offset >= n_msgRegisters {
            if let Some(ipc_buffer) = self.lookup_mut_ipc_buffer(true) {
                ipc_buffer.msg[offset] = reg;
                return offset + 1;
            } else {
                return n_msgRegisters;
            }
        } else {
            self.set_register(msgRegister[offset], reg);
            return offset + 1;
        }
    }


    pub fn set_lookup_fault_mrs(&mut self, offset: usize, fault: &lookup_fault_t) -> usize {
        let luf_type = fault.get_type();
        let i = self.set_mr(offset, luf_type + 1);
        if offset == seL4_CapFault_LookupFailureType {
            assert_eq!(offset + 1, seL4_CapFault_BitsLeft);
            assert_eq!(offset + 2, seL4_CapFault_DepthMismatch_BitsFound);
            assert_eq!(offset + 2, seL4_CapFault_GuardMismatch_GuardFound);
            assert_eq!(offset + 3, seL4_CapFault_GuardMismatch_BitsFound);
        } else {
            assert_eq!(offset, 1);
        }
        match fault.get_lookup_fault_type() {
            crate::common::fault::LookupFaultType::InvaildRoot => i,
            crate::common::fault::LookupFaultType::MissingCap => {
                self.set_mr(offset + 1, fault.missing_cap_get_bits_left())
            },
            crate::common::fault::LookupFaultType::DepthMismatch => {
                self.set_mr(offset + 1, fault.depth_mismatch_get_bits_left());
                self.set_mr(offset + 2, fault.depth_mismatch_get_bits_found())
            },
            crate::common::fault::LookupFaultType::GuardMismatch => {
                self.set_mr(offset + 1, fault.guard_mismatch_get_bits_left());
                self.set_mr(offset + 2, fault.guard_mismatch_get_guard_found());
                self.set_mr(offset + 3, fault.guard_mismatch_get_bits_found())
            }
        }
    }

    pub fn get_receive_slot(&mut self) -> Option<&'static mut cte_t> {
        if let Some(buffer) = self.lookup_ipc_buffer(true) {
            let cptr= buffer.receiveCNode;
            let lu_ret = self.lookup_slot(cptr);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                return None;
            }
            let cnode_cap = unsafe { &(*lu_ret.slot).cap };
            let lus_ret = resolve_address_bits(cnode_cap, buffer.receiveIndex, buffer.receiveDepth);
            if unlikely(lus_ret.status != exception_t::EXCEPTION_NONE || lus_ret.bitsRemaining != 0) {
                return None;
            }
            return Some(convert_to_mut_type_ref::<cte_t>(lus_ret.slot as usize))
        }
        return None
    }

    #[inline]
    pub fn copy_mrs(&self, receiver: &mut tcb_t, length: usize) -> usize {
        let mut i = 0;
        while i < length && i < n_msgRegisters {
            receiver.set_register(msgRegister[i], self.get_register(msgRegister[i]));
            i += 1;
        }
        if let (Some(send_buffer), Some(recv_buffer)) = (self.lookup_ipc_buffer(false), receiver.lookup_mut_ipc_buffer(true)) {
            unsafe {
                let recv_ptr = recv_buffer as *mut seL4_IPCBuffer as *mut usize;
                let send_ptr = send_buffer as *const seL4_IPCBuffer as *const usize;
                while i < length {
                    *(recv_ptr.add(i + 1)) = *(send_ptr.add(i + 1));
                    i += 1;
                }
            }
        }
        i
    }

    #[inline]
    pub fn copy_fault_mrs(&self, receiver: &mut Self, id: usize, length: usize) {
        let len = if length < n_msgRegisters {
            length
        } else {
            n_msgRegisters
        };
        let mut i = 0;
        while i < len {
            receiver.set_register(msgRegister[i], self.get_register(fault_messages[id][i]));
            i += 1;
        }
        if let Some(buffer) = receiver.lookup_mut_ipc_buffer(true) {
            while i < length {
                buffer.msg[i] = self.get_register(fault_messages[id][i]);
                i += 1;
            }
        }
    }

    #[inline]
    pub fn copy_fault_mrs_for_reply(&self, receiver: &mut Self, id: usize, length: usize) {
        let len = if length < n_msgRegisters {
            length
        } else {
            n_msgRegisters
        };
        let mut i = 0;
        while i < len {
            receiver.set_register(fault_messages[id][i], self.get_register(msgRegister[i]));
            i += 1;
        }
        if let Some(buffer) = self.lookup_ipc_buffer(false) {
            while i < length {
                receiver.set_register(fault_messages[id][i], buffer.msg[i]);
                i += 1;
            }
        }
    }

    #[inline]
    pub fn copy_syscall_fault_mrs(&self, receiver: &mut Self) {
        self.copy_fault_mrs(receiver, MessageID_Syscall, n_syscallMessage)
    }
    
    #[inline]
    pub fn copy_exeception_fault_mrs(&self, receiver: &mut Self) {
        self.copy_fault_mrs(receiver, MessageID_Exception, n_exceptionMessage)
    }

    #[inline]
    pub fn set_fault_mrs(&self, receiver: &mut Self) -> usize {
        match self.tcbFault.get_fault_type() {
            crate::common::fault::FaultType::CapFault => {
                receiver.set_mr(seL4_CapFault_IP, self.get_register(FaultIP));
                receiver.set_mr(seL4_CapFault_Addr, self.tcbFault.cap_fault_get_address());
                receiver.set_mr(seL4_CapFault_InRecvPhase, self.tcbFault.cap_fault_get_in_receive_phase());
                receiver.set_lookup_fault_mrs(seL4_CapFault_LookupFailureType, &self.tcbLookupFailure)
            },
            crate::common::fault::FaultType::UnknownSyscall => {
                self.copy_syscall_fault_mrs(receiver);
                receiver.set_mr(n_syscallMessage, self.tcbFault.unknown_syscall_get_syscall_number())
            },
            crate::common::fault::FaultType::UserException => {
                self.copy_exeception_fault_mrs(receiver);
                receiver.set_mr(n_exceptionMessage, self.tcbFault.user_exeception_get_number());
                receiver.set_mr(n_exceptionMessage + 1, self.tcbFault.user_exeception_get_code())
            },
            crate::common::fault::FaultType::VMFault => {
                receiver.set_mr(seL4_VMFault_IP, self.get_register(FaultIP));
                receiver.set_mr(seL4_VMFault_Addr, self.tcbFault.vm_fault_get_address());
                receiver.set_mr(seL4_VMFault_PrefetchFault, self.tcbFault.vm_fault_get_instruction_fault());
                receiver.set_mr(seL4_VMFault_FSR, self.tcbFault.vm_fault_get_fsr())
            },
            _ => {
                panic!("invalid fault")
            }
        }
    }

}

#[inline]
pub fn getCSpace(ptr: usize, i: usize) -> *mut cte_t {
    getCSpaceMutRef(ptr, i) as *mut cte_t
}

#[inline]
pub fn getCSpaceMutRef(ptr: usize, i: usize) -> &'static mut cte_t {
    unsafe {
        let thread =&mut *( ptr as *mut tcb_t);
        thread.get_cspace_mut_ref(i)
    }
}

#[inline]
pub fn setRegister(thread: *mut tcb_t, reg: usize, w: usize) {
    unsafe {
        (*thread).set_register(reg, w)
    }
}

#[inline]
pub fn getRegister(thread: *const tcb_t, reg: usize) -> usize {
    unsafe {
        (*thread).get_register(reg)
     }
}

#[inline]
pub fn set_thread_state(tcb: &mut tcb_t, state: ThreadState) {
    tcb.tcbState.set_ts_type(state as usize);
    schedule_tcb(tcb);
}

#[no_mangle]
pub fn setThreadState(tptr: *mut tcb_t, ts: usize) {
    // panic!("should not be invoked!")
    unsafe {
        set_thread_state(&mut *tptr, core::mem::transmute::<u8, ThreadState>(ts as u8))
    }
}

#[no_mangle]
pub fn setupReplyMaster(_thread: *mut tcb_t) {
    panic!("should not be invoked")
}


#[no_mangle]
pub fn lookupIPCBuffer(isReceiver: bool, thread: *mut tcb_t) -> usize {
    unsafe {
        match (*thread).lookup_ipc_buffer(isReceiver) {
            Some(ipc_buffer) => {
                return ipc_buffer as *const seL4_IPCBuffer as usize
            }
            _ => 0
        }
    }
}