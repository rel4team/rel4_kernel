pub const ra: usize = 0;
pub const sp: usize = 1;
const gp: usize = 2;
const tp: usize = 3;
pub const TLS_BASE: usize = 3;
const t0: usize = 4;
const t1: usize = 5;
const t2: usize = 6;
const s0: usize = 7;
const s1: usize = 8;
const a0: usize = 9;
pub const capRegister: usize = 9;
pub const badgeRegister: usize = 9;
pub const msgInfoRegister: usize = 10;
const a1: usize = 10;
const a2: usize = 11;
const a3: usize = 12;
const a4: usize = 13;
const a5: usize = 14;
const a6: usize = 15;
const a7: usize = 16;
const s2: usize = 17;
const s3: usize = 18;
const s4: usize = 19;
const s5: usize = 20;
const s6: usize = 21;
const s7: usize = 22;
const s8: usize = 23;
const s9: usize = 24;
const s10: usize = 25;
const s11: usize = 26;
const t3: usize = 27;
const t4: usize = 28;
const t5: usize = 29;
const t6: usize = 30;
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
