//! Constants used in rCore

use crate::{BIT, MASK};

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

pub const PPTR_BASE: usize = 0xFFFFFFC000000000;
pub const PADDR_BASE: usize = 0x0;
pub const PT_INDEX_BITS: usize = 9;
pub const PT_OFFSET_BITS: usize = 12;
pub const CONFIG_PT_LEVELS: usize = 3;
pub const seL4_PageBits: usize = 12;
pub const PAGE_BITS: usize = seL4_PageBits;
pub const PPTR_TOP: usize = 0xFFFFFFFF80000000;
pub const physBase: usize = 0x80000000;
pub const KERNEL_ELF_PADDR_BASE: usize = physBase + 0x4000000;
pub const KERNEL_ELF_BASE: usize = PPTR_TOP + (KERNEL_ELF_PADDR_BASE & MASK!(30));
pub const KDEV_BASE: usize = 0xFFFFFFFFC0000000;
pub const KS_LOG_PPTR: usize = 0xFFFFFFFFFFE00000;
pub const PPTR_BASE_OFFSET: usize = PPTR_BASE - PADDR_BASE;
pub const PADDR_TOP: usize = PPTR_TOP - PPTR_BASE_OFFSET;
pub const KERNEL_ELF_BASE_OFFSET: usize = KERNEL_ELF_BASE - KERNEL_ELF_PADDR_BASE;
pub const seL4_PageTableBits: usize = 12;
pub const asidLowBits: usize = 9;
pub const asidHighBits: usize = 7;
pub const IT_ASID: usize = 1;
pub const RISCVPageBits: usize = 12;
pub const RISCVMegaPageBits: usize = 21;
pub const RISCVGigaPageBits: usize = 30;
pub const wordRadix: usize = 6;
pub const wordBits: usize = BIT!(wordRadix);
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

pub const SSTATUS_SPIE: usize = 0x00000020;
pub const SSTATUS_SPP: usize = 0x00000010;
pub const CONFIG_KERNEL_STACK_BITS: usize = 12;

pub const ksDomScheduleLength: usize = 1;

pub const SchedulerAction_ResumeCurrentThread: usize = 0;
pub const SchedulerAction_ChooseNewThread: usize = 1;

pub const MAX_NUM_FREEMEM_REG: usize = 16;
pub const NUM_RESERVED_REGION: usize = 3;
pub const MAX_NUM_RESV_REG: usize = MAX_NUM_FREEMEM_REG + NUM_RESERVED_REGION;

pub const CONFIG_ROOT_CNODE_SIZE_BITS: usize = 13;
pub const seL4_SlotBits: usize = 5;
pub const seL4_PML4Bits: usize = 12;
pub const seL4_VSpaceBits: usize = seL4_PML4Bits;
pub const seL4_TCBBits: usize = 12;
pub const seL4_IPCBufferSizeBits: usize = 10;
pub const BI_FRAME_SIZE_BITS: usize = 12;
pub const seL4_ASIDPoolBits: usize = 12;
pub const seL4_NumInitialCaps: usize = 14;

pub const seL4_CapNull: usize = 0;
pub const seL4_CapInitThreadTCB: usize = 1;
pub const seL4_CapInitThreadCNode: usize = 2;
pub const seL4_CapInitThreadVspace: usize = 3;
pub const seL4_CapIRQControl: usize = 4;
pub const seL4_CapASIDControl: usize = 5;
pub const seL4_CapInitThreadASIDPool: usize = 6;
pub const seL4_CapInitThreadIPCBuffer: usize = 10;
pub const seL4_CapDomain: usize = 11;

pub const SIE_STIE: usize = 5;
pub const SIE_SEIE: usize = 9;

pub const seL4_MsgMaxLength: usize = 120;
pub const msgInfoRegister: usize = 10;
pub const badgeRegister: usize = 9;
pub const seL4_MsgExtraCapBits: usize = 2;
pub const seL4_MsgMaxExtraCaps: usize = BIT!(seL4_MsgExtraCapBits) - 1;
pub const n_msgRegisters: usize = 4;
pub const seL4_CapRightsBits:usize=4;

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
pub const RISCVASIDAssign: usize = 36;
pub const RISCVIRQIssueIRQHandlerTrigger: usize = 37;
pub const nArchInvocationLabels: usize = 38;

pub const n_frameRegisters: usize = 16;
pub const n_gpRegisters: usize = 16;
pub const n_exceptionMessage: usize = 2;
pub const n_syscallMessage: usize = 10;

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

pub const CONFIG_RESET_CHUNK_BITS:usize=8;
pub const seL4_MinUntypedBits:usize=4;
pub const seL4_MaxUntypedBits:usize=38;