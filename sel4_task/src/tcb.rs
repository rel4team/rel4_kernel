use core::intrinsics::{likely, unlikely};

use sel4_common::arch::{
    fault_messages, msgInfoRegister, msgRegister, n_contextRegisters, n_exceptionMessage,
    n_msgRegisters, n_syscallMessage, FaultIP, NextIP, SSTATUS,
};
use sel4_common::fault::*;
use sel4_common::message_info::seL4_MessageInfo_t;
use sel4_common::utils::{convert_to_mut_type_ref, pageBitsForSize};
#[cfg(feature = "ENABLE_SMP")]
use sel4_common::BIT;
use sel4_common::MASK;
use sel4_cspace::interface::{cap_t, cte_insert, cte_t, mdb_node_t, resolve_address_bits, CapTag};
use sel4_vspace::{pptr_t, set_vm_root, VMReadOnly, VMReadWrite};

use crate::tcb_queue::tcb_queue_t;
use sel4_common::sel4_config::*;
use sel4_common::structures::{exception_t, seL4_IPCBuffer};

use super::scheduler::{
    addToBitmap, get_currenct_thread, possible_switch_to, ready_queues_index, removeFromBitmap,
    rescheduleRequired, schedule_tcb, set_current_thread,
};
use super::structures::lookupSlot_raw_ret_t;

use super::thread_state::*;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
/// Structure for the architecture registers of specific TCB
pub struct arch_tcb_t {
    /// The registers context of the TCB
    pub registers: [usize; n_contextRegisters],
}

impl Default for arch_tcb_t {
    fn default() -> Self {
        let mut registers = [0; n_contextRegisters];
        registers[SSTATUS] = 0x00040020;
        Self { registers }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
/// Structure for the TCB
pub struct tcb_t {
    /// The architecture registers of the TCB
    pub tcbArch: arch_tcb_t,
    /// The state of the TCB
    pub tcbState: thread_state_t,
    /// The bound notification of the TCB
    pub tcbBoundNotification: usize,
    /// The fault of the TCB
    pub tcbFault: seL4_Fault_t,
    /// The lookup fault of the TCB
    pub tcbLookupFailure: lookup_fault_t,
    /// The domain of the TCB
    pub domain: usize,
    /// The maximum controlled priority of the TCB
    pub tcbMCP: usize,
    /// The priority of the TCB
    pub tcbPriority: usize,
    /// The time slice of the TCB
    pub tcbTimeSlice: usize,
    /// The falut handler of the TCB
    pub tcbFaultHandler: usize,
    /// The IPC buffer of the TCB
    pub tcbIPCBuffer: usize,
    /// the affinity of the TCB in SMP
    #[cfg(feature = "ENABLE_SMP")]
    pub tcbAffinity: usize,
    /// The next TCB in the scheduling queue
    pub tcbSchedNext: usize,
    /// The previous TCB in the scheduling queue
    pub tcbSchedPrev: usize,
    /// The next TCB in the EP queue
    pub tcbEPNext: usize,
    /// The previous TCB in the EP queue
    pub tcbEPPrev: usize,
}

impl tcb_t {
    #[inline]
    /// Get i th cspace of the TCB, unmutable reference
    pub fn get_cspace(&self, i: usize) -> &'static cte_t {
        unsafe {
            let p = ((self.get_ptr()) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &*(p.add(i))
        }
    }

    #[inline]
    /// Initialize the TCB
    pub fn init(&mut self) {
        self.tcbArch = arch_tcb_t::default();
    }

    #[inline]
    /// Get i th cspace of the TCB, mutable reference
    pub fn get_cspace_mut_ref(&mut self, i: usize) -> &'static mut cte_t {
        unsafe {
            let p = ((self as *mut tcb_t as usize) & !MASK!(seL4_TCBBits)) as *mut cte_t;
            &mut *(p.add(i))
        }
    }

    #[inline]
    /// Get the current state of the TCB
    pub fn get_state(&self) -> ThreadState {
        unsafe { core::mem::transmute::<u8, ThreadState>(self.tcbState.get_ts_type() as u8) }
    }

    #[inline]
    /// Check if the TCB is stopped by checking the state
    pub fn is_stopped(&self) -> bool {
        match self.get_state() {
            ThreadState::ThreadStateInactive
            | ThreadState::ThreadStateBlockedOnNotification
            | ThreadState::ThreadStateBlockedOnReceive
            | ThreadState::ThreadStateBlockedOnReply
            | ThreadState::ThreadStateBlockedOnSend => true,

            _ => false,
        }
    }

    #[inline]
    /// Check if the TCB is runnable by checking the state
    pub fn is_runnable(&self) -> bool {
        match self.get_state() {
            ThreadState::ThreadStateRunning | ThreadState::ThreadStateRestart => true,
            _ => false,
        }
    }

    #[inline]
    /// Check if the TCB is current by comparing the tcb pointer
    pub fn is_current(&self) -> bool {
        self.get_ptr() == get_currenct_thread().get_ptr()
    }

    #[inline]
    /// Set the register of the TCB
    /// # Arguments
    /// * `reg` - The register index.
    /// * `w` - The value to set.
    pub fn set_register(&mut self, reg: usize, w: usize) {
        self.tcbArch.registers[reg] = w;
    }

    #[inline]
    /// Get the register value of the TCB
    /// # Arguments
    /// * `reg` - The register index.
    /// # Returns
    /// The value of the register.
    pub fn get_register(&self, reg: usize) -> usize {
        self.tcbArch.registers[reg]
    }

    #[inline]
    /// Set the maximum controlled priority of the TCB
    pub fn set_mcp_priority(&mut self, mcp: usize) {
        self.tcbMCP = mcp;
    }

    #[inline]
    /// Set the priority of the TCB, and reschedule if the thread is runnable and not current
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
    /// Bind the notification of the TCB
    /// # Arguments
    /// * `addr` - The address of the notification to bind.
    pub fn bind_notification(&mut self, addr: pptr_t) {
        self.tcbBoundNotification = addr;
    }

    #[inline]
    /// Unbind the notification of the TCB(just set the bound notification to 0)
    pub fn unbind_notification(&mut self) {
        self.tcbBoundNotification = 0;
    }

    #[inline]
    /// Set the domain of the TCB.
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

    /// Enqueue the TCB to the scheduling queue
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
    /// Get the scheduling queue by index from ksReadyQueues
    pub fn get_sched_queue(&mut self, index: usize) -> &'static mut tcb_queue_t {
        unsafe {
            #[cfg(feature = "ENABLE_SMP")]
            {
                use super::scheduler::ksSMP;
                &mut ksSMP[self.tcbAffinity].ksReadyQueues[index]
            }
            #[cfg(not(feature = "ENABLE_SMP"))]
            {
                use super::ksReadyQueues;
                &mut ksReadyQueues[index]
            }
        }
    }

    #[inline]
    /// Get the CPU of the TCB, 0 if not in SMP, tcbAffinity if in SMP
    pub fn get_cpu(&self) -> usize {
        #[cfg(feature = "ENABLE_SMP")]
        {
            self.tcbAffinity
        }
        #[cfg(not(feature = "ENABLE_SMP"))]
        {
            0
        }
    }

    /// Dequeue the TCB from the scheduling queue
    pub fn sched_dequeue(&mut self) {
        if self.tcbState.get_tcb_queued() != 0 {
            let dom = self.domain;
            let prio = self.tcbPriority;
            let idx = ready_queues_index(dom, prio);
            let queue = self.get_sched_queue(idx);
            if self.tcbSchedPrev != 0 {
                convert_to_mut_type_ref::<tcb_t>(self.tcbSchedPrev).tcbSchedNext =
                    self.tcbSchedNext;
            } else {
                queue.head = self.tcbSchedNext as *mut tcb_t as usize;
                if likely(self.tcbSchedNext == 0) {
                    removeFromBitmap(self.get_cpu(), dom, prio);
                }
            }
            if self.tcbSchedNext != 0 {
                convert_to_mut_type_ref::<tcb_t>(self.tcbSchedNext).tcbSchedPrev =
                    self.tcbSchedPrev;
            } else {
                queue.tail = self.tcbSchedPrev as *mut tcb_t as usize;
            }
            // unsafe { ksReadyQueues[idx] = queue; }
            self.tcbState.set_tcb_queued(0);
        }
    }

    /// Append the TCB to the scheduling queue tail
    /// # Note
    /// This function is as same as `sched_enqueue`, but it is used for the EP queue
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
        use super::scheduler::{ksCurDomain, ksSMP};
        use sel4_common::utils::{convert_to_type_ref, cpu_id};
        unsafe {
            if self.tcbAffinity != cpu_id() && self.domain == ksCurDomain {
                let target_current =
                    convert_to_type_ref::<tcb_t>(ksSMP[self.tcbAffinity].ksCurThread);
                if ksSMP[self.tcbAffinity].ksIdleThread == ksSMP[self.tcbAffinity].ksCurThread
                    || self.tcbPriority > target_current.tcbPriority
                {
                    ksSMP[cpu_id()].ipiReschedulePending |= BIT!(self.tcbAffinity);
                }
            }
        }
    }

    /// Set the VM root of the TCB
    pub fn set_vm_root(&self) -> Result<(), lookup_fault_t> {
        // let threadRoot = &(*getCSpace(thread as usize, tcbVTable)).cap;
        let thread_root = self.get_cspace(tcbVTable).cap;
        set_vm_root(&thread_root)
    }

    #[inline]
    /// Switch to the TCB(set current thread to self)
    pub fn switch_to_this(&mut self) {
        // if hart_id() == 0 {
        //     debug!("switch_to_this: {:#x}", self.get_ptr());
        // }
        let _ = self.set_vm_root();
        self.sched_dequeue();
        set_current_thread(self);
    }

    #[inline]
    /// Get the pointer of the TCB
    /// # Returns
    /// The raw pointer of the TCB
    pub fn get_ptr(&self) -> pptr_t {
        self as *const tcb_t as usize
    }

    #[inline]
    /// Look up the slot of the TCB
    /// # Arguments
    /// * `cap_ptr` - The capability pointer to look up
    /// # Returns
    /// The lookup result structure
    pub fn lookup_slot(&self, cap_ptr: usize) -> lookupSlot_raw_ret_t {
        let thread_root = self.get_cspace(tcbCTable).cap;
        let res_ret = resolve_address_bits(&thread_root, cap_ptr, wordBits);
        lookupSlot_raw_ret_t {
            status: res_ret.status,
            slot: res_ret.slot,
        }
    }

    #[inline]
    /// Setup the reply master of the TCB
    pub fn setup_reply_master(&mut self) {
        let slot = self.get_cspace_mut_ref(tcbReply);
        if slot.cap.get_cap_type() == CapTag::CapNullCap {
            slot.cap = cap_t::new_reply_cap(1, 1, self.get_ptr());
            slot.cteMDBNode = mdb_node_t::new(0, 1, 1, 0);
        }
    }

    #[inline]
    /// Susupend the TCB, set the state to ThreadStateInactive and dequeue from the scheduling queue
    pub fn suspend(&mut self) {
        if self.get_state() == ThreadState::ThreadStateRunning {
            self.set_register(FaultIP, self.get_register(NextIP));
        }
        // setThreadState(self as *mut Self, ThreadStateInactive);
        set_thread_state(self, ThreadState::ThreadStateInactive);
        self.sched_dequeue();
    }

    #[inline]
    /// Restart the TCB, set the state to ThreadStateRestart and enqueue to the scheduling queue waiting for reschedule
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
    /// Setup the caller cap of the TCB
    /// # Arguments
    /// * `sender` - The sender TCB
    /// * `can_grant` - If the cap can be granted
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
        cte_insert(
            &cap_t::new_reply_cap(can_grant as usize, 0, sender.get_ptr()),
            reply_slot,
            caller_slot,
        );
    }

    #[inline]
    /// Delete the caller cap of the TCB
    pub fn delete_caller_cap(&mut self) {
        let caller_slot = self.get_cspace_mut_ref(tcbCaller);
        caller_slot.delete_one();
    }

    /// Look up the IPC buffer of the TCB
    /// # Arguments
    /// * `is_receiver` - If the TCB is receiver
    /// # Returns
    /// The IPC buffer of the TCB
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
            return Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(
                base_ptr + (w_buffer_ptr & MASK!(page_bits)),
            ));
        }
        return None;
    }

    /// Look up the extra caps of the TCB
    /// # Arguments
    /// * `res` - The result array to store the extra caps
    /// # Returns
    /// The result of the lookup represented by seL4_Fault_t
    pub fn lookup_extra_caps(
        &self,
        res: &mut [pptr_t; seL4_MsgMaxExtraCaps],
    ) -> Result<(), seL4_Fault_t> {
        let info = seL4_MessageInfo_t::from_word_security(self.get_register(msgInfoRegister));
        if let Some(buffer) = self.lookup_ipc_buffer(false) {
            let length = info.get_extra_caps();
            let mut i = 0;
            while i < length {
                let cptr = buffer.get_extra_cptr(i);
                let lu_ret = self.lookup_slot(cptr);
                if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
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

    /// Look up the extra caps of the TCB with IPC buffer
    /// # Arguments
    /// * `res` - The result array to store the extra caps
    /// * `buf` - The IPC buffer to look up
    /// # Returns
    /// The result of the lookup represented by seL4_Fault_t
    pub fn lookup_extra_caps_with_buf(
        &self,
        res: &mut [pptr_t; seL4_MsgMaxExtraCaps],
        buf: Option<&seL4_IPCBuffer>,
    ) -> Result<(), seL4_Fault_t> {
        let info = seL4_MessageInfo_t::from_word_security(self.get_register(msgInfoRegister));
        if let Some(buffer) = buf {
            let length = info.get_extra_caps();
            let mut i = 0;
            while i < length {
                let cptr = buffer.get_extra_cptr(i);
                let lu_ret = self.lookup_slot(cptr);
                if unlikely(lu_ret.status != exception_t::EXCEPTION_NONE) {
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

    /// As same as `lookup_ipc_buffer`, but the result is mutable reference
    pub fn lookup_mut_ipc_buffer(
        &mut self,
        is_receiver: bool,
    ) -> Option<&'static mut seL4_IPCBuffer> {
        let w_buffer_ptr = self.tcbIPCBuffer;
        let buffer_cap = self.get_cspace(tcbBuffer).cap;
        if buffer_cap.get_cap_type() != CapTag::CapFrameCap {
            return None;
        }

        let vm_rights = buffer_cap.get_frame_vm_rights();
        if vm_rights == VMReadWrite || (!is_receiver && vm_rights == VMReadOnly) {
            let base_ptr = buffer_cap.get_frame_base_ptr();
            let page_bits = pageBitsForSize(buffer_cap.get_frame_size());
            return Some(convert_to_mut_type_ref::<seL4_IPCBuffer>(
                base_ptr + (w_buffer_ptr & MASK!(page_bits)),
            ));
        }
        return None;
    }

    #[inline]
    /// Set the message info register of the TCB
    /// # Arguments
    /// * `offset` - The offset of the message info register, if the offset is larger than n_msgRegisters, set to the IPC buffer
    /// * `reg` - The value to set
    /// # Returns
    /// The next offset
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

    /// Set the lookup fault to the msg registers of the TCB
    /// # Arguments
    /// * `offset` - The offset of the lookup fault
    /// * `fault` - The lookup fault to set
    /// # Returns
    /// The next offset
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
            LookupFaultType::InvaildRoot => i,
            LookupFaultType::MissingCap => {
                self.set_mr(offset + 1, fault.missing_cap_get_bits_left())
            }
            LookupFaultType::DepthMismatch => {
                self.set_mr(offset + 1, fault.depth_mismatch_get_bits_left());
                self.set_mr(offset + 2, fault.depth_mismatch_get_bits_found())
            }
            LookupFaultType::GuardMismatch => {
                self.set_mr(offset + 1, fault.guard_mismatch_get_bits_left());
                self.set_mr(offset + 2, fault.guard_mismatch_get_guard_found());
                self.set_mr(offset + 3, fault.guard_mismatch_get_bits_found())
            }
        }
    }

    /// Get the receive slot of the TCB
    /// # Returns
    /// The mutable ref of receive slot of the TCB
    pub fn get_receive_slot(&mut self) -> Option<&'static mut cte_t> {
        if let Some(buffer) = self.lookup_ipc_buffer(true) {
            let cptr = buffer.receiveCNode;
            let lu_ret = self.lookup_slot(cptr);
            if lu_ret.status != exception_t::EXCEPTION_NONE {
                return None;
            }
            let cnode_cap = unsafe { &(*lu_ret.slot).cap };
            let lus_ret = resolve_address_bits(cnode_cap, buffer.receiveIndex, buffer.receiveDepth);
            if unlikely(lus_ret.status != exception_t::EXCEPTION_NONE || lus_ret.bitsRemaining != 0)
            {
                return None;
            }
            return Some(convert_to_mut_type_ref::<cte_t>(lus_ret.slot as usize));
        }
        return None;
    }

    #[inline]
    /// Copy the message registers and ipc buffer(if valid) of the TCB to the receiver
    /// # Arguments
    /// * `receiver` - The receiver TCB
    /// * `length` - The length of the message registers to copy
    /// # Returns
    /// The number of registers(contains ipc buffer) copied
    pub fn copy_mrs(&self, receiver: &mut tcb_t, length: usize) -> usize {
        let mut i = 0;
        while i < length && i < n_msgRegisters {
            receiver.set_register(msgRegister[i], self.get_register(msgRegister[i]));
            i += 1;
        }
        if let (Some(send_buffer), Some(recv_buffer)) = (
            self.lookup_ipc_buffer(false),
            receiver.lookup_mut_ipc_buffer(true),
        ) {
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
    /// Copy the falut messages and ipc buffer(if valid) of the TCB to the receiver
    /// # Arguments
    /// * `receiver` - The receiver TCB
    /// * `id` - The fault message id
    /// * `length` - The length of the message registers to copy
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
    /// Copy the falut messages for reply and ipc buffer(if valid) of the TCB to the receiver for reply
    /// # Arguments
    /// * `receiver` - The receiver TCB
    /// * `id` - The fault message id
    /// * `length` - The length of the message registers to copy
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
    /// Copy the syscall fault messages of the TCB to the receiver
    pub fn copy_syscall_fault_mrs(&self, receiver: &mut Self) {
        self.copy_fault_mrs(receiver, MessageID_Syscall, n_syscallMessage)
    }

    #[inline]
    /// Copy the exception fault messages of the TCB to the receiver
    pub fn copy_exeception_fault_mrs(&self, receiver: &mut Self) {
        self.copy_fault_mrs(receiver, MessageID_Exception, n_exceptionMessage)
    }

    #[inline]
    /// Set the fault message registers of the TCB to the receiver
    /// # Arguments
    /// * `receiver` - The receiver TCB
    pub fn set_fault_mrs(&self, receiver: &mut Self) -> usize {
        match self.tcbFault.get_fault_type() {
            FaultType::CapFault => {
                receiver.set_mr(seL4_CapFault_IP, self.get_register(FaultIP));
                receiver.set_mr(seL4_CapFault_Addr, self.tcbFault.cap_fault_get_address());
                receiver.set_mr(
                    seL4_CapFault_InRecvPhase,
                    self.tcbFault.cap_fault_get_in_receive_phase(),
                );
                receiver
                    .set_lookup_fault_mrs(seL4_CapFault_LookupFailureType, &self.tcbLookupFailure)
            }
            FaultType::UnknownSyscall => {
                self.copy_syscall_fault_mrs(receiver);
                receiver.set_mr(
                    n_syscallMessage,
                    self.tcbFault.unknown_syscall_get_syscall_number(),
                )
            }
            FaultType::UserException => {
                self.copy_exeception_fault_mrs(receiver);
                receiver.set_mr(
                    n_exceptionMessage,
                    self.tcbFault.user_exeception_get_number(),
                );
                receiver.set_mr(
                    n_exceptionMessage + 1,
                    self.tcbFault.user_exeception_get_code(),
                )
            }
            FaultType::VMFault => {
                receiver.set_mr(seL4_VMFault_IP, self.get_register(FaultIP));
                receiver.set_mr(seL4_VMFault_Addr, self.tcbFault.vm_fault_get_address());
                receiver.set_mr(
                    seL4_VMFault_PrefetchFault,
                    self.tcbFault.vm_fault_get_instruction_fault(),
                );
                receiver.set_mr(seL4_VMFault_FSR, self.tcbFault.vm_fault_get_fsr())
            }
            _ => {
                panic!("invalid fault")
            }
        }
    }
}

#[inline]
/// Set the thread state of the TCB
/// # Arguments
/// * `tcb` - The TCB to set
/// * `state` - The state
pub fn set_thread_state(tcb: &mut tcb_t, state: ThreadState) {
    tcb.tcbState.set_ts_type(state as usize);
    schedule_tcb(tcb);
}
