use log::error;

use core::panic::PanicInfo;
use sel4_common::arch::shutdown;

/// Print `[ERROR 0] rel4_kernel: PANICED` if panic is detected
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        error!(
            "Panicked at {}:{} {}",
            location.file(),
            location.line(),
            info.message().unwrap()
        );
    } else {
        error!("[kernel] Panicked: {}", info.message().unwrap());
    }
    error!("rel4_kernel: PANICED");
    shutdown()
}
