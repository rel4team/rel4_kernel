macro_rules! read_csr {
    ($csr_number:literal) => {
        /// Reads the CSR
        #[inline]
        unsafe fn _read() -> usize {
            let r: usize;
            core::arch::asm!(concat!("csrrs {0}, ", stringify!($csr_number), ", x0"), out(reg) r);
            r
        }
    };
}

macro_rules! read_csr_as {
    ($register:ident, $csr_number:literal) => {
        read_csr!($csr_number);

        /// Reads the CSR
        #[inline]
        pub fn read() -> $register {
            $register {
                bits: unsafe { _read() },
            }
        }
    };
}

macro_rules! read_csr_as_usize {
    ($csr_number:literal) => {
        read_csr!($csr_number);

        /// Reads the CSR
        #[inline]
        pub fn read() -> usize {
            unsafe { _read() }
        }
    };
}

macro_rules! write_csr {
    ($csr_number:literal) => {
        /// Writes the CSR
        #[inline]
        #[allow(unused_variables)]
        unsafe fn _write(bits: usize) {
            core::arch::asm!(concat!("csrrw x0, ", stringify!($csr_number), ", {0}"), in(reg) bits);
        }
    };
}

macro_rules! write_csr_as_usize {
    ($csr_number:literal) => {
        write_csr!($csr_number);

        /// Writes the CSR
        #[inline]
        pub fn write(bits: usize) {
            unsafe { _write(bits) }
        }
    };
}

macro_rules! set {
    ($csr_number:literal) => {
        /// Set the CSR
        #[inline]
        #[allow(unused_variables)]
        unsafe fn _set(bits: usize) {
            core::arch::asm!(concat!("csrrs x0, ", stringify!($csr_number), ", {0}"), in(reg) bits);
        }
    };
}

macro_rules! clear {
    ($csr_number:literal) => {
        /// Clear the CSR
        #[inline]
        #[allow(unused_variables)]
        unsafe fn _clear(bits: usize) {
            core::arch::asm!(concat!("csrrc x0, ", stringify!($csr_number), ", {0}"), in(reg) bits);
        }
    };
}

macro_rules! set_csr {
    ($(#[$attr:meta])*, $set_field:ident, $e:expr) => {
        $(#[$attr])*
        #[inline]
        pub unsafe fn $set_field() {
            _set($e);
        }
    };
}

macro_rules! clear_csr {
    ($(#[$attr:meta])*, $clear_field:ident, $e:expr) => {
        $(#[$attr])*
        #[inline]
        pub unsafe fn $clear_field() {
            _clear($e);
        }
    };
}

macro_rules! set_clear_csr {
    ($(#[$attr:meta])*, $set_field:ident, $clear_field:ident, $e:expr) => {
        set_csr!($(#[$attr])*, $set_field, $e);
        clear_csr!($(#[$attr])*, $clear_field, $e);
    }
}
