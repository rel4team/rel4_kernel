//! Constants used in rCore

use common::{sel4_config::wordBits, BIT};

pub const USER_STACK_SIZE: usize = 4096 * 2;
pub const KERNEL_STACK_SIZE: usize = 4096 * 10;
pub const KERNEL_HEAP_SIZE: usize = 0x800000;
pub const MEMORY_END: usize = 0x88000000;
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;
pub const MAX_SYSCALL_NUM: usize = 500;
pub const MAX_APP_NUM: usize = 16;

pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
pub const TRAP_CONTEXT: usize = TRAMPOLINE - PAGE_SIZE;
pub const CLOCK_FREQ: usize = 12500000;
pub const BIG_STRIDE: isize = 1024;
pub const APP_BASE_ADDRESS: usize = 0x84000000;
pub const APP_SIZE_LIMIT: usize = 0x20000;
pub const PT_OFFSET_BITS: usize = 12;
pub const CONFIG_TIME_SLICE: usize = 5;
pub const seL4_LargePageBits: usize = 21;
pub const seL4_HugePageBits: usize = 30;
pub const KDEV_BASE: usize = 0xFFFFFFFFC0000000;
pub const KS_LOG_PPTR: usize = 0xFFFFFFFFFFE00000;
pub const RISCVPageBits: usize = 12;
pub const RISCVMegaPageBits: usize = 21;
pub const RISCVGigaPageBits: usize = 30;
pub const CONFIG_NUM_DOMAINS: usize = 1;
pub const CONFIG_NUM_PRIORITIES: usize = 256;
pub const L2_BITMAP_SIZE: usize = (CONFIG_NUM_PRIORITIES + wordBits - 1) / wordBits;
pub const NUM_READY_QUEUES: usize = CONFIG_NUM_DOMAINS * CONFIG_NUM_PRIORITIES;
pub const CONFIG_MAX_NUM_NODES: usize = 1;
pub const KERNEL_STACK_ALIGNMENT: usize = 4096;
pub const tcbCTable: usize = 0;
pub const tcbVTable: usize = 1;
pub const tcbReply: usize = 2;
pub const tcbCaller: usize = 3;
pub const tcbBuffer: usize = 4;
pub const tcbCNodeEntries: usize = 5;
pub const TCB_SIZE_BITS: usize = seL4_TCBBits - 1;
pub const TCB_OFFSET: usize = BIT!(TCB_SIZE_BITS);
pub const SSTATUS_SPIE: usize = 0x00000020;
pub const SSTATUS_SPP: usize = 0x00000100;
pub const CONFIG_KERNEL_STACK_BITS: usize = 12;

//FIXME:this constant is generated , maybe need to transfer from C code
pub const CONFIG_PADDR_USER_DEVICE_TOP: usize = 549755813888;


pub const MAX_NUM_FREEMEM_REG: usize = 16;
pub const NUM_RESERVED_REGIONS: usize = 3;
pub const MAX_NUM_RESV_REG: usize = MAX_NUM_FREEMEM_REG + NUM_RESERVED_REGIONS;

pub const CONFIG_ROOT_CNODE_SIZE_BITS: usize = 13;
pub const seL4_PML4Bits: usize = 12;
pub const seL4_VSpaceBits: usize = seL4_PML4Bits;
pub const seL4_TCBBits: usize = 10;
pub const seL4_IPCBufferSizeBits: usize = 10;
pub const BI_FRAME_SIZE_BITS: usize = 12;
pub const seL4_ASIDPoolBits: usize = 12;

pub const seL4_CapNull: usize = 0;
pub const seL4_CapInitThreadTCB: usize = 1;
pub const seL4_CapInitThreadCNode: usize = 2;
pub const seL4_CapInitThreadVspace: usize = 3;
pub const seL4_CapIRQControl: usize = 4;
pub const seL4_CapASIDControl: usize = 5;
pub const seL4_CapInitThreadASIDPool: usize = 6;
pub const seL4_CapIOPortControl: usize = 7;
pub const seL4_CapIOSpace: usize = 8;
pub const seL4_CapBootInfoFrame: usize = 9;
pub const seL4_CapInitThreadIPCBuffer: usize = 10;
pub const seL4_CapDomain: usize = 11;
pub const seL4_CapSMMUSIDControl: usize = 12;
pub const seL4_CapSMMUCBControl: usize = 13;
pub const seL4_NumInitialCaps: usize = 14;

pub const SIP_SSIP: usize = 1;
pub const SIP_MSIP: usize = 3;
pub const SIP_STIP: usize = 5;
pub const SIP_MTIP: usize = 7;
pub const SIP_SEIP: usize = 9;
pub const SIP_MEIP: usize = 11;

pub const SIE_SSIE: usize = 1;
pub const SIE_MSIE: usize = 3;
pub const SIE_STIE: usize = 5;
pub const SIE_MTIE: usize = 7;
pub const SIE_SEIE: usize = 9;
pub const SIE_MEIE: usize = 11;

pub const seL4_MsgMaxLength: usize = 120;
pub const msgInfoRegister: usize = 10;
pub const badgeRegister: usize = 9;
pub const seL4_MsgLengthBits:usize =7;
pub const seL4_MsgExtraCapBits: usize = 2;
pub const seL4_MsgMaxExtraCaps: usize = BIT!(seL4_MsgExtraCapBits) - 1;
pub const n_msgRegisters: usize = 4;

pub const RISCVInstructionMisaligned: usize = 0;
pub const RISCVInstructionAccessFault: usize = 1;
pub const RISCVInstructionIllegal: usize = 2;
pub const RISCVBreakPoint: usize = 3;
pub const RISCVLoadAccessFault: usize = 5;
pub const RISCVAddressMisaligned: usize = 6;
pub const RISCVStoreAccessFault: usize = 7;
pub const RISCVEnvCall: usize = 8;
pub const RISCVInstructionPageFault: usize = 12;
pub const RISCVLoadPageFault: usize = 13;
pub const RISCVStorePageFault: usize = 15;
pub const RISCVSupervisorTimer: usize = 9223372036854775813;

//invocation
pub const InvalidInvocation: usize = 0;
pub const UntypedRetype: usize = 1;
pub const TCBReadRegisters: usize = 2;
pub const TCBWriteRegisters: usize = 3;
pub const TCBCopyRegisters: usize = 4;
pub const TCBConfigure: usize = 5;
pub const TCBSetPriority: usize = 6;
pub const TCBSetMCPriority: usize = 7;
pub const TCBSetSchedParams: usize = 8;
pub const TCBSetIPCBuffer: usize = 9;
pub const TCBSetSpace: usize = 10;
pub const TCBSuspend: usize = 11;
pub const TCBResume: usize = 12;
pub const TCBBindNotification: usize = 13;
pub const TCBUnbindNotification: usize = 14;
pub const TCBSetTLSBase: usize = 15;
pub const CNodeRevoke: usize = 16;
pub const CNodeDelete: usize = 17;
pub const CNodeCancelBadgedSends: usize = 18;
pub const CNodeCopy: usize = 19;
pub const CNodeMint: usize = 20;
pub const CNodeMove: usize = 21;
pub const CNodeMutate: usize = 22;
pub const CNodeRotate: usize = 23;
pub const CNodeSaveCaller: usize = 24;
pub const IRQIssueIRQHandler: usize = 25;
pub const IRQAckIRQ: usize = 26;
pub const IRQSetIRQHandler: usize = 27;
pub const IRQClearIRQHandler: usize = 28;
pub const DomainSetSet: usize = 29;
pub const RISCVPageTableMap: usize = 30;
pub const RISCVPageTableUnmap: usize = 31;
pub const RISCVPageMap: usize = 32;
pub const RISCVPageUnmap: usize = 33;
pub const RISCVPageGetAddress: usize = 34;
pub const RISCVASIDControlMakePool: usize = 35;
pub const RISCVASIDPoolAssign: usize = 36;
pub const RISCVIRQIssueIRQHandlerTrigger: usize = 37;
pub const nArchInvocationLabels: usize = 38;

pub const n_frameRegisters: usize = 16;
pub const n_gpRegisters: usize = 16;
pub const n_exceptionMessage: usize = 2;
pub const n_syscallMessage: usize = 10;
pub const MAX_MSG_SIZE: usize = n_syscallMessage;

pub const CopyRegisters_suspendSource: usize = 0;
pub const CopyRegisters_resumeTarget: usize = 1;
pub const CopyRegisters_transferFrame: usize = 2;
pub const CopyRegisters_transferInteger: usize = 3;

pub const ReadRegisters_suspend: usize = 0;
pub const frameRegisters: [usize; n_frameRegisters] =
    [33, 0, 1, 2, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26];
pub const gpRegisters: [usize; n_gpRegisters] =
    [9, 10, 11, 12, 13, 14, 15, 16, 4, 5, 6, 27, 28, 29, 30, 3];
pub const msgRegister: [usize; n_msgRegisters] = [11, 12, 13, 14];
pub const thread_control_update_priority: usize = 0x1;
pub const thread_control_update_ipc_buffer: usize = 0x2;
pub const thread_control_update_space: usize = 0x4;
pub const thread_control_update_mcp: usize = 0x8;

pub const CONFIG_RESET_CHUNK_BITS: usize = 8;

pub const seL4_WordBits: usize = 64;

pub const seL4_UserTop: usize = 0x00007fffffffffff;
pub const USER_TOP: usize = seL4_UserTop;

//IRQConstants
pub const PLIC_IRQ_OFFSET: usize = 0;
pub const PLIC_MAX_IRQ: usize = 0;
pub const KERNEL_TIMER_IRQ: usize = 1;
pub const maxIRQ: usize = KERNEL_TIMER_IRQ;

pub const irqInvalid: usize = 0;

// irq_state
pub const IRQInactive: usize = 0;
pub const IRQSignal: usize = 1;
pub const IRQTimer: usize = 2;
pub const IRQReserved: usize = 3;

pub const SEL4_BOOTINFO_HEADER_FDT: usize = 6;
pub const SEL4_BOOTINFO_HEADER_PADDING: usize = 0;
pub const CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS: usize = 230;

pub const seL4_MaxPrio: usize = 255;

pub const TIMER_CLOCK_HZ: usize = 10000000;
pub const MS_IN_S: usize = 1000;
pub const RESET_CYCLES: usize = (TIMER_CLOCK_HZ / MS_IN_S) * 2;

pub const seL4_NoError: usize = 0;
pub const seL4_InvalidArgument: usize = 1;
pub const seL4_InvalidCapability: usize = 2;
pub const seL4_IllegalOperation: usize = 3;
pub const seL4_RangeError: usize = 4;
pub const seL4_AlignmentError: usize = 5;
pub const seL4_FailedLookup: usize = 6;
pub const seL4_TruncatedMessage: usize = 7;
pub const seL4_DeleteFirst: usize = 8;
pub const seL4_RevokeFirst: usize = 9;
pub const seL4_NotEnoughMemory: usize = 10;
pub const seL4_NumErrors: usize = 11;

pub const seL4_Fault_NullFault: usize = 0;
pub const seL4_Fault_CapFault: usize = 1;
pub const seL4_Fault_UnknownSyscall: usize = 2;
pub const seL4_Fault_UserException: usize = 3;
pub const seL4_Fault_VMFault: usize = 5;

pub const EPState_Idle: usize = 0;
pub const EPState_Send: usize = 1;
pub const EPState_Recv: usize = 2;

pub const seL4_CapFault_IP: usize = 0;
pub const seL4_CapFault_Addr: usize = 1;
pub const seL4_CapFault_InRecvPhase: usize = 2;
pub const seL4_CapFault_LookupFailureType: usize = 3;
pub const seL4_CapFault_BitsLeft: usize = 4;
pub const seL4_CapFault_DepthMismatch_BitsFound: usize = 5;
pub const seL4_CapFault_GuardMismatch_GuardFound: usize = seL4_CapFault_DepthMismatch_BitsFound;
pub const seL4_CapFault_GuardMismatch_BitsFound: usize = 6;

pub const MessageID_Syscall: usize = 0;
pub const MessageID_Exception: usize = 1;

pub const NtfnState_Idle: usize = 0;
pub const NtfnState_Waiting: usize = 1;
pub const NtfnState_Active: usize = 2;

pub const seL4_MinPrio: usize = 0;

pub const CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION: usize = 100;
pub const CONFIG_RETYPE_FAN_OUT_LIMIT: usize = 256;

pub const seL4_UntypedObject: usize = 0;
pub const seL4_TCBObject: usize = 1;
pub const seL4_EndpointObject: usize = 2;
pub const seL4_NotificationObject: usize = 3;
pub const seL4_CapTableObject: usize = 4;
pub const seL4_NonArchObjectTypeCount: usize = 5;
pub const seL4_ObjectTypeCount: usize = 9;

pub const SysCall: isize = -1;
pub const SysReplyRecv: isize = -2;
pub const SysSend: isize = -3;
pub const SysNBSend: isize = -4;
pub const SysRecv: isize = -5;
pub const SysReply: isize = -6;
pub const SysYield: isize = -7;
pub const SysNBRecv: isize = -8;

//seL4_VMFault_Msg
pub const seL4_VMFault_IP: usize = 0;
pub const seL4_VMFault_Addr: usize = 1;
pub const seL4_VMFault_PrefetchFault: usize = 2;
pub const seL4_VMFault_FSR: usize = 3;
pub const seL4_VMFault_Length: usize = 4;

