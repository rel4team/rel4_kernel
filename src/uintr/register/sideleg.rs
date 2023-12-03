//! sideleg register

write_csr_as_usize!(0x103);
read_csr_as_usize!(0x103);

set!(0x103);
clear!(0x103);

set_clear_csr!(
    /// User Software Interrupt Pending
    , set_usoft, clear_usoft, 1 << 0);
set_clear_csr!(
    /// User External Interrupt Pending
    , set_uext, clear_uext, 1 << 8);