use common::structures::{exception_t, lookup_fault_t};
use cspace::interface::{cap_t, cte_t};

use crate::{
    config::{
        seL4_MsgMaxExtraCaps, seL4_MsgMaxLength, CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS,
        MAX_NUM_FREEMEM_REG, MAX_NUM_RESV_REG,
    },
    kernel::thread::n_contextRegisters,
};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct seL4_BootInfoHeader {
    pub id: usize,
    pub len: usize,
}

#[derive(Copy, Clone)]
pub struct region_t {
    pub start: usize,
    pub end: usize,
}

#[derive(Copy, Clone)]
pub struct p_region_t {
    pub start: usize,
    pub end: usize,
}

#[derive(Copy, Clone)]
pub struct v_region_t {
    pub start: usize,
    pub end: usize,
}

pub type seL4_SlotPos = usize;

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct seL4_SlotRegion {
    pub start: seL4_SlotPos,
    pub end: seL4_SlotPos,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct seL4_IPCBuffer {
    tag: usize,
    msg: [usize; seL4_MsgMaxLength],
    userData: usize,
    caps_or_badges: [usize; seL4_MsgMaxExtraCaps],
    receiveCNode: usize,
    receiveIndex: usize,
    receiveDepth: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct seL4_UntypedDesc {
    pub paddr: usize,
    pub sizeBits: u8,
    pub isDevice: u8,
    pub padding: [u8; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct seL4_BootInfo {
    pub extraLen: usize,
    pub nodeID: usize,
    pub numNodes: usize,
    pub numIOPTLevels: usize,
    pub ipcBuffer: *const seL4_IPCBuffer,
    pub empty: seL4_SlotRegion,
    pub sharedFrames: seL4_SlotRegion,
    pub userImageFrames: seL4_SlotRegion,
    pub userImagePaging: seL4_SlotRegion,
    pub ioSpaceCaps: seL4_SlotRegion,
    pub extraBIPages: seL4_SlotRegion,
    pub initThreadCNodeSizeBits: usize,
    pub initThreadDomain: usize,
    pub untyped: seL4_SlotRegion,
    pub untypedList: [seL4_UntypedDesc; CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ndks_boot_t {
    pub reserved: [p_region_t; MAX_NUM_RESV_REG],
    pub resv_count: usize,
    pub freemem: [region_t; MAX_NUM_FREEMEM_REG],
    pub bi_frame: *mut seL4_BootInfo,
    pub slot_pos_cur: seL4_SlotPos,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct rootserver_mem_t {
    pub cnode: usize,
    pub vspace: usize,
    pub asid_pool: usize,
    pub ipc_buf: usize,
    pub boot_info: usize,
    pub extra_bi: usize,
    pub tcb: usize,
    pub paging: region_t,
}

#[repr(C)]
#[derive(Debug, PartialEq, Copy, Clone)]
pub struct thread_state_t {
    pub words: [usize; 3],
}

#[derive(PartialEq)]
pub enum cap_tag_t {
    cap_null_cap = 0,
    cap_untyped_cap = 2,
    cap_endpoint_cap = 4,
    cap_notification_cap = 6,
    cap_reply_cap = 8,
    cap_cnode_cap = 10,
    cap_thread_cap = 12,
    cap_irq_control_cap = 14,
    cap_irq_handler_cap = 16,
    cap_zombie_cap = 18,
    cap_domain_cap = 20,
    cap_frame_cap = 1,
    cap_page_table_cap = 3,
    cap_asid_control_cap = 11,
    cap_asid_pool_cap = 13,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct dschedule_t {
    pub domain: usize,
    pub length: usize,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct finaliseSlot_ret {
    pub status: exception_t,
    pub success: bool,
    pub cleanupInfo: cap_t,
}

impl Default for finaliseSlot_ret {
    fn default() -> Self {
        finaliseSlot_ret {
            status: exception_t::EXCEPTION_NONE,
            success: true,
            cleanupInfo: cap_t::default(),
        }
    }
}




#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct finaliseCap_ret {
    pub remainder: cap_t,
    pub cleanupInfo: cap_t,
}

impl Default for finaliseCap_ret {
    fn default() -> Self {
        finaliseCap_ret {
            remainder: cap_t::default(),
            cleanupInfo: cap_t::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct endpoint_t {
    pub words: [usize; 2],
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct create_frames_of_region_ret_t {
    pub region: seL4_SlotRegion,
    pub success: bool,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct arch_tcb_t {
    pub registers: [usize; n_contextRegisters],
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct seL4_Fault_t {
    pub words: [usize; 2],
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct tcb_t {
    pub tcbArch: arch_tcb_t,
    pub tcbState: thread_state_t,
    pub tcbBoundNotification: *mut notification_t,
    pub tcbFault: seL4_Fault_t,
    pub tcbLookupFailure: lookup_fault_t,
    pub domain: usize,
    pub tcbMCP: usize,
    pub tcbPriority: usize,
    pub tcbTimeSlice: usize,
    pub tcbFaultHandler: usize,
    pub tcbIPCBuffer: usize,
    pub tcbSchedNext: usize,
    pub tcbSchedPrev: usize,
    pub tcbEPNext: usize,
    pub tcbEPPrev: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct tcb_queue_t {
    pub head: *mut tcb_t,
    pub tail: *mut tcb_t,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct notification_t {
    pub words: [usize; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct resolveAddressBits_ret_t {
    pub status: exception_t,
    pub slot: *mut cte_t,
    pub bitsRemaining: usize,
}

impl Default for resolveAddressBits_ret_t {
    fn default() -> Self {
        resolveAddressBits_ret_t {
            status: exception_t::EXCEPTION_NONE,
            slot: 0 as *mut cte_t,
            bitsRemaining: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct lookupCap_ret_t {
    pub status: exception_t,
    pub cap: cap_t,
}

impl Default for lookupCap_ret_t {
    fn default() -> Self {
        lookupCap_ret_t {
            status: exception_t::EXCEPTION_NONE,
            cap: cap_t::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct cap_transfer_t {
    pub ctReceiveRoot: usize,
    pub ctReceiveIndex: usize,
    pub ctReceiveDepth: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct lookupCapAndSlot_ret_t {
    pub status: exception_t,
    pub cap: cap_t,
    pub slot: *mut cte_t,
}

impl Default for lookupCapAndSlot_ret_t {
    fn default() -> Self {
        lookupCapAndSlot_ret_t {
            status: exception_t::EXCEPTION_NONE,
            cap: cap_t::default(),
            slot: 0 as *mut cte_t,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]

pub struct lookupSlot_raw_ret_t {
    pub status: exception_t,
    pub slot: *mut cte_t,
}

impl Default for lookupSlot_raw_ret_t {
    fn default() -> Self {
        lookupSlot_raw_ret_t {
            status: exception_t::EXCEPTION_NONE,
            slot: 0 as *mut cte_t,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct lookupSlot_ret_t {
    pub status: exception_t,
    pub slot: *mut cte_t,
}

impl Default for lookupSlot_ret_t {
    fn default() -> Self {
        lookupSlot_ret_t {
            status: exception_t::EXCEPTION_NONE,
            slot: 0 as *mut cte_t,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct syscall_error_t {
    pub invalidArgumentNumber: usize,
    pub invalidCapNumber: usize,
    pub rangeErrorMin: usize,
    pub rangeErrorMax: usize,
    pub memoryLeft: usize,
    pub failedLookupWasSource: usize,
    pub _type: usize,
}


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct seL4_MessageInfo_t {
    pub words: [usize; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct vm_attributes_t {
    pub words: [usize; 1],
}


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct extra_caps_t {
    pub excaprefs: [*mut cte_t; seL4_MsgMaxExtraCaps],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct seL4_CNode_CapData_t {
    pub words: [usize; 1],
}
