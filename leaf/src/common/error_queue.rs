use std::error::Error;
use lazy_static::lazy_static;
use crate::proto::client_config::{ErrorRustMessage, ErrorType, RustMessage, RustMessageType};
use std::sync::{Mutex};
use log::error;
use protobuf::Clear;
lazy_static! {
    static ref RUST_ERROR_MESSAGE: Mutex<Option<String>> = Mutex::new(Option::None);
}
// pub fn push_error(error: ErrorType, msg: String) -> Result<(), Box<dyn Error>> {}
pub fn push_error(error: ErrorType, msg: String) {
    error!("push_error msg: {:?}", &msg);
    let mut error_rust_message = ErrorRustMessage::default();
    error_rust_message.set_error_type(error);
    error_rust_message.set_error_msg(msg);
    let error_rust_message = serde_json::to_string(&error_rust_message);
    match error_rust_message {
        Ok(message) => {
            if let Err(e) = set_error_rust_message(message) {
                // 处理 set_error_rust_message 的错误，可以记录日志或者其他操作
                error!("Error setting error message: {:?}", e);
            }
        }
        Err(e) => {
            // 处理 serde_json::to_string 的错误，可以记录日志或者其他操作
            error!("Error serializing error message: {:?}", e);
        }
    }
}



pub fn take_error_message() -> String {
    match RUST_ERROR_MESSAGE.lock() {
        Ok(mut guard) => {
            match guard.take() {
                Some(error_message) => error_message,
                None => "".to_owned(),
            }
        }
        Err(e) => {
            error!("take_error_message error {:?}", e);
            "".to_owned()
        }
    }
}


fn set_error_rust_message(msg: String) -> Result<(), Box<dyn Error>>{
    RUST_ERROR_MESSAGE.lock()?.replace(msg);
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::Arc;

    #[test]
    fn test_error_handling() {
        let error_type = ErrorType::change_password_error;

        // 创建 Mutex 包装的 RUST_ERROR_MESSAGE
        // 启动多个线程调用 push_error 方法
        let threads1: Vec<_> = (0..4).map(|i| {
            thread::spawn(move || {
                let msg = format!("change_password_error {i}" );

                super::push_error(error_type, msg.to_string());
                println!("push error :{msg}");
            })
        }).collect();

        let threads2: Vec<_> = (0..4).map(|_| {
            thread::spawn(move || {
                let string = take_error_message();
                println!("take :{string}");
            })
        }).collect();

        for thread in threads1 {
            thread.join().unwrap();
        }
        // 等待所有线程完成
        for thread in threads2 {
            thread.join().unwrap();
        }
    }
}