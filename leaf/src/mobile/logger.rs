use std::{
    ffi,
    io::{self, Write},
};

use bytes::BytesMut;

#[cfg(any(target_os = "ios", target_os = "macos"))]
//use super::bindings::{asl_log, ASL_LEVEL_NOTICE};

#[cfg(target_os = "android")]
//use super::bindings::{__android_log_print, android_LogPriority_ANDROID_LOG_VERBOSE};

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn log_out(data: &[u8]) {
    // unsafe {
    //     let s = match ffi::CString::new(data) {
    //         Ok(s) => s,
    //         Err(_) => return,
    //     };
    // };
}

#[cfg(target_os = "android")]
fn log_out(data: &[u8]) {
    unsafe {
        let s = match ffi::CString::new(data) {
            Ok(s) => s,
            Err(_) => return,
        };
    }
}

pub struct ConsoleWriter(pub BytesMut);

impl Default for ConsoleWriter {
    fn default() -> Self {
        ConsoleWriter(BytesMut::new())
    }
}

unsafe impl Send for ConsoleWriter {}

impl Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buf);
        if let Some(i) = memchr::memchr(b'\n', &self.0) {
            let _ = self.0.split_to(i + 1);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
