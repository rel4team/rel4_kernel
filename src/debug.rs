use log::debug;
use crate::common::sel4_config::tcbCNodeEntries;
use crate::common::utils::{convert_to_mut_type_ref, convert_to_type_ref, convert_to_mut_type_ref_unsafe};
use crate::task_manager::{FaultIP, ksDebugTCBs, tcb_t, ThreadState};

const MAX_DEBUG_THREAD_NAME: usize = 64;
struct DebugTCB {
    next: usize,
    prev: usize,
    name: [char; MAX_DEBUG_THREAD_NAME],
}

impl tcb_t {
    #[inline]
    pub fn get_ks_debug_tcbs_head(&self) -> &Self {
        #[cfg(not(feature = "ENABLE_SMP"))]
        return convert_to_mut_type_ref_unsafe::<Self>(unsafe { ksDebugTCBs });
        #[cfg(feature = "ENABLE_SMP")]
        return unsafe {
            use crate::task_manager::ksSMP;
            convert_to_mut_type_ref_unsafe::<Self>(ksSMP[self.get_cpu()].ksDebugTCBs)
        }
    }

    #[inline]
    pub fn set_ks_debug_tcbs_head(&self, debug_tcb_ptr: usize) {
        #[cfg(not(feature = "ENABLE_SMP"))]
        unsafe { ksDebugTCBs = debug_tcb_ptr; }
        #[cfg(feature = "ENABLE_SMP")]
        unsafe {
            use crate::task_manager::ksSMP;
            ksSMP[self.get_cpu()].ksDebugTCBs = debug_tcb_ptr;
        }
    }

    pub fn set_name(&mut self, name: &str) {
        let debug_tcb = DebugTCB::from_tcb(self);
        for (i, c) in name.chars().enumerate() {
            if i < MAX_DEBUG_THREAD_NAME && c as u8 != 0 {
                debug_tcb.name[i] = c;
            } else {
                break;
            }
        }
    }

    pub fn debug_print(&self) {
        debug!("tcb name: {:?}", DebugTCB::from_tcb(self).name);
        let state = match self.get_state() {
            ThreadState::ThreadStateInactive => "inactive",
            ThreadState::ThreadStateRunning => "running",
            ThreadState::ThreadStateRestart => "restart",
            ThreadState::ThreadStateBlockedOnReceive => "blocked on recv",
            ThreadState::ThreadStateBlockedOnSend => "blocked on send",
            ThreadState::ThreadStateBlockedOnReply => "blocked on reply",
            ThreadState::ThreadStateBlockedOnNotification => "blocked on ntfn",
            ThreadState::ThreadStateIdleThreadState => "idle",
            ThreadState::ThreadStateExited => "exit",
            _ => {
                "other"
            }
        };
        debug!("state: {}, restart_pc: {:#x}, prio: {}, core: {}", state, self.get_register(FaultIP),
                self.tcbPriority, self.get_cpu());
    }
}

impl DebugTCB {
    #[inline]
    pub fn from_tcb(tcb: &tcb_t) -> &mut Self {
        convert_to_mut_type_ref::<DebugTCB>(tcb.get_cspace(tcbCNodeEntries).get_ptr())
    }
}

#[no_mangle]
pub fn tcb_debug_remove(tcb: &tcb_t) {
    let debug_tcb = DebugTCB::from_tcb(tcb);
    let ks_debug_tcb = tcb.get_ks_debug_tcbs_head();
    if tcb.get_ptr() == ks_debug_tcb.get_ptr() {
        tcb.set_ks_debug_tcbs_head(DebugTCB::from_tcb(ks_debug_tcb).next);
    } else {
        assert_ne!(debug_tcb.prev, 0);
        DebugTCB::from_tcb(convert_to_type_ref::<tcb_t>(debug_tcb.prev)).next = debug_tcb.next;
    }

    if debug_tcb.next != 0 {
        DebugTCB::from_tcb(convert_to_type_ref::<tcb_t>(debug_tcb.next)).prev = debug_tcb.prev;
    }
    debug_tcb.next = 0;
    debug_tcb.prev = 0;
}

#[no_mangle]
pub fn tcb_debug_append(tcb: &tcb_t) {
    let debug_tcb = DebugTCB::from_tcb(tcb);
    debug_tcb.prev = 0;
    let ks_debug_tcbs_head = tcb.get_ks_debug_tcbs_head();
    debug_tcb.next = ks_debug_tcbs_head.get_ptr();

    if ks_debug_tcbs_head.get_ptr() != 0 {
        DebugTCB::from_tcb(ks_debug_tcbs_head).prev = tcb.get_ptr();
    }
    tcb.set_ks_debug_tcbs_head(tcb.get_ptr());
}