pub mod crypto;
pub mod io;
pub mod net;
pub mod resolver;
pub mod sniff;
pub mod sync_valid_routes;
pub mod error_queue;


#[cfg(target_os = "macos")]
pub mod cmd_macos;
#[cfg(target_os = "macos")]
pub use cmd_macos as cmd;

#[cfg(target_os = "linux")]
pub mod cmd_linux;
pub mod circular_queue;

#[cfg(target_os = "linux")]
pub use cmd_linux as cmd;
