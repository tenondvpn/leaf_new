use crate::Error;
use crate::proto::client_config::ErrorType;

pub fn push_error() {
    let error = ErrorType::change_password_error;
    let msg = "change_password_error";
}
