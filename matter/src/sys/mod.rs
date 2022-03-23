#[cfg(target_os = "macos")]
mod sys_macos;
#[cfg(target_os = "macos")]
pub use self::sys_macos::*;

#[cfg(target_os = "linux")]
mod sys_linux;
#[cfg(target_os = "linux")]
pub use self::sys_linux::*;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod posix;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use self::posix::*;
