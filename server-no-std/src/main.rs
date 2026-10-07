// Skeleton only, deliberately -- no Modbus logic yet. #![no_std] means no
// std::io/std::net/std::sync::Mutex/String/Vec (the last two need `alloc`,
// not pulled in yet either); #![no_main] means no Rust-generated runtime
// glue, just a bare `extern "C" fn main` that the system's own libc startup
// code (crt0/__libc_start_main, already linked in by default on this
// target) calls directly. Still a real, runnable Linux executable -- see
// this crate's Cargo.toml doc comment for why panic = "abort" is required
// and why this is its own standalone workspace.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

// rustc passes -nodefaultlibs under #![no_std], so nothing links libc by
// default -- but Scrt1.o (always linked in on this target) calls
// __libc_start_main before it ever reaches our `main` below, so libc must
// still be linked explicitly.
#[link(name = "c")]
unsafe extern "C" {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    0
}
