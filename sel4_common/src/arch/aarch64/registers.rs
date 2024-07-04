// // enum _register {
// //     X0                          = 0,    /* 0x00 */
// //     capRegister                 = 0,
// pub const capRegister:usize = 0;
// //     badgeRegister               = 0,
// pub const badgeRegister:usize = 0;
// //     X1                          = 1,    /* 0x08 */
// //     msgInfoRegister             = 1,
// pub const msgInfoRegister:usize = 1;
// //     X2                          = 2,    /* 0x10 */
// //     X3                          = 3,    /* 0x18 */
// //     X4                          = 4,    /* 0x20 */
// //     X5                          = 5,    /* 0x28 */
// //     X6                          = 6,    /* 0x30 */
// // #ifdef CONFIG_KERNEL_MCS
// //     replyRegister               = 6,
// // #endif
// //     X7                          = 7,    /* 0x38 */
// //     X8                          = 8,    /* 0x40 */
// // #ifdef CONFIG_KERNEL_MCS
// //     nbsendRecvDest              = 8,
// // #endif
// //     X9                          = 9,    /* 0x48 */
// //     X10                         = 10,   /* 0x50 */
// //     X11                         = 11,   /* 0x58 */
// //     X12                         = 12,   /* 0x60 */
// //     X13                         = 13,   /* 0x68 */
// //     X14                         = 14,   /* 0x70 */
// //     X15                         = 15,   /* 0x78 */
// //     X16                         = 16,   /* 0x80 */
// //     X17                         = 17,   /* 0x88 */
// //     X18                         = 18,   /* 0x90 */
// //     X19                         = 19,   /* 0x98 */
// //     X20                         = 20,   /* 0xa0 */
// //     X21                         = 21,   /* 0xa8 */
// //     X22                         = 22,   /* 0xb0 */
// //     X23                         = 23,   /* 0xb8 */
// //     X24                         = 24,   /* 0xc0 */
// //     X25                         = 25,   /* 0xc8 */
// //     X26                         = 26,   /* 0xd0 */
// //     X27                         = 27,   /* 0xd8 */
// //     X28                         = 28,   /* 0xe0 */
// //     X29                         = 29,   /* 0xe8 */
// //     X30                         = 30,   /* 0xf0 */
// //     LR                          = 30,

// //     /* End of GP registers, the following are additional kernel-saved state. */
// //     SP_EL0                      = 31,   /* 0xf8 */
// pub const SP_EL0:usize = 31;
// //     ELR_EL1                     = 32,   /* 0x100 */
// pub const ELR_EL1:usize = 32;
// //     NextIP                      = 32,   /* LR_svc */
// pub const NextIP:usize = 32;
// //     SPSR_EL1                    = 33,   /* 0x108 */
// pub const SPSR_EL1:usize = 33;
// //     FaultIP                     = 34,   /* 0x110 */
// pub const FaultIP:usize = 34;
// //     /* user readable/writable thread ID register.
// //      * name comes from the ARM manual */
// //     TPIDR_EL0                   = 35,
// pub const TPIDR_EL0:usize = 35;
// //     TLS_BASE                    = TPIDR_EL0,
// //     /* user readonly thread ID register. */
// //     TPIDRRO_EL0                 = 36,
// //     n_contextRegisters          = 37,
// // };
pub const ra: usize = 0;
pub const sp: usize = 1;
// const gp: usize = 2;
// const tp: usize = 3;
pub const TLS_BASE: usize = 3;
// const t0: usize = 4;
// const t1: usize = 5;
// const t2: usize = 6;
// const s0: usize = 7;
// const s1: usize = 8;
// const a0: usize = 9;
pub const capRegister: usize = 9;
pub const badgeRegister: usize = 9;
pub const msgInfoRegister: usize = 10;
// const a1: usize = 10;
// const a2: usize = 11;
// const a3: usize = 12;
// const a4: usize = 13;
// const a5: usize = 14;
// const a6: usize = 15;
// const a7: usize = 16;
// const s2: usize = 17;
// const s3: usize = 18;
// const s4: usize = 19;
// const s5: usize = 20;
// const s6: usize = 21;
// const s7: usize = 22;
// const s8: usize = 23;
// const s9: usize = 24;
// const s10: usize = 25;
// const s11: usize = 26;
// const t3: usize = 27;
// const t4: usize = 28;
// const t5: usize = 29;
// const t6: usize = 30;
pub const SCAUSE: usize = 31;
pub const SSTATUS: usize = 32;
pub const FaultIP: usize = 33;
pub const NextIP: usize = 34;
pub const n_contextRegisters: usize = 35;
pub const n_msgRegisters: usize = 4;
pub const msgRegister: [usize; n_msgRegisters] = [11, 12, 13, 14];

pub const SSTATUS_SPIE: usize = 0x00000020;
pub const SSTATUS_SPP: usize = 0x00000100;

pub const n_syscallMessage: usize = 10;
pub const n_exceptionMessage: usize = 2;
pub const MAX_MSG_SIZE: usize = n_syscallMessage;
pub const fault_messages: [[usize; MAX_MSG_SIZE]; 2] = [
    [33, 1, 0, 9, 10, 11, 12, 13, 14, 15],
    [33, 1, 0, 0, 0, 0, 0, 0, 0, 0],
];
