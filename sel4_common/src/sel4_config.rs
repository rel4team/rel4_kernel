//! This module contains the configuration settings for sel4_common.
use crate::{BIT, MASK};

pub const wordRadix: usize = 6;
pub const wordBits: usize = BIT!(wordRadix);
pub const seL4_EndpointBits: usize = 4;
pub const seL4_NotificationBits: usize = 4;
pub const seL4_SlotBits: usize = 5;
pub const seL4_ReplyBits: usize = 4;
pub const seL4_MinUntypedBits: usize = 4;
pub const seL4_MaxUntypedBits: usize = 38;

// page table relevant
pub const PT_SIZE_BITS: usize = 12;
pub const PAGE_BITS: usize = seL4_PageBits;
pub const RISCV_4K_Page: usize = 0;
pub const RISCV_Mega_Page: usize = 1;
pub const RISCV_Giga_Page: usize = 2;
pub const RISCV_Tera_Page: usize = 3;

pub const ARM_Small_Page: usize = 0;
pub const ARM_Large_Page: usize = 1;
pub const ARM_Huge_Page: usize = 2;

pub const RISCVPageBits: usize = 12;
pub const RISCVMegaPageBits: usize = 21;
pub const RISCVGigaPageBits: usize = 30;

pub const ARMSmallPageBits: usize = 12;
pub const ARMLargePageBits: usize = 21;
pub const ARMHugePageBits: usize = 30;

pub const PT_INDEX_BITS: usize = 9;
pub const CONFIG_PT_LEVELS: usize = 3;
pub const seL4_PageBits: usize = 12;
pub const seL4_PageTableBits: usize = 12;
pub const seL4_HugePageBits: usize = 30;
pub const seL4_LargePageBits: usize = 21;

// ASID relevant
pub const asidLowBits: usize = 9;
pub const asidHighBits: usize = 7;
pub const asidInvalid: usize = 0;
pub const nASIDPools: usize = BIT!(asidHighBits);
pub const ASID_BITS: usize = asidHighBits + asidLowBits;
pub const IT_ASID: usize = 1;

// boot 相关的常数
pub const PPTR_TOP: usize = 0xFFFFFFFF80000000;
pub const physBase: usize = 0x80000000;
pub const KERNEL_ELF_PADDR_BASE: usize = physBase + 0x4000000;
pub const KERNEL_ELF_BASE: usize = PPTR_TOP + (KERNEL_ELF_PADDR_BASE & MASK!(30));
pub const KERNEL_ELF_BASE_OFFSET: usize = KERNEL_ELF_BASE - KERNEL_ELF_PADDR_BASE;
pub const PPTR_BASE: usize = 0xFFFFFFC000000000;
pub const PADDR_BASE: usize = 0x0;
pub const PPTR_BASE_OFFSET: usize = PPTR_BASE - PADDR_BASE;
pub const PADDR_TOP: usize = PPTR_TOP - PPTR_BASE_OFFSET;

// scheduler relevant
pub const CONFIG_NUM_DOMAINS: usize = 1;
pub const CONFIG_NUM_PRIORITIES: usize = 256;
pub const L2_BITMAP_SIZE: usize = (CONFIG_NUM_PRIORITIES + wordBits - 1) / wordBits;
pub const NUM_READY_QUEUES: usize = CONFIG_NUM_DOMAINS * CONFIG_NUM_PRIORITIES;
pub const CONFIG_TIME_SLICE: usize = 5;

// TCB relevant
pub const seL4_TCBBits: usize = 10;
pub const TCB_SIZE_BITS: usize = seL4_TCBBits - 1;
pub const TCB_OFFSET: usize = BIT!(TCB_SIZE_BITS);
pub const tcbCTable: usize = 0;
pub const tcbVTable: usize = 1;
pub const tcbReply: usize = 2;
pub const tcbCaller: usize = 3;
pub const tcbBuffer: usize = 4;
pub const tcbCNodeEntries: usize = 5;

// 多核相关
#[cfg(not(feature = "ENABLE_SMP"))]
pub const CONFIG_MAX_NUM_NODES: usize = 1;

#[cfg(feature = "ENABLE_SMP")]
pub const CONFIG_MAX_NUM_NODES: usize = 4;

// 错误码
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

// msg info
pub const seL4_MsgMaxLength: usize = 120;
pub const seL4_MsgExtraCapBits: usize = 2;
pub const seL4_MsgMaxExtraCaps: usize = BIT!(seL4_MsgExtraCapBits) - 1;
pub const MessageID_Syscall: usize = 0;
pub const MessageID_Exception: usize = 1;

pub const seL4_IPCBufferSizeBits: usize = 10;

pub const CONFIG_RESET_CHUNK_BITS: usize = 8;

pub const CONFIG_KERNEL_STACK_BITS: usize = 12;
