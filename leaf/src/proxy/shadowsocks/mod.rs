use std::io;
use protobuf::Message;
use crate::proto::server_config::PasswordResponse;

mod crypto;
pub mod shadow;

#[cfg(feature = "inbound-shadowsocks")]
pub mod inbound;
#[cfg(feature = "outbound-shadowsocks")]
pub mod outbound;
pub mod ss_router;
// pub mod preconnect;

pub fn convert_from_with_error_tag(buf: &mut [u8]) -> io::Result<PasswordResponse>{
    // Check if there are at least 2 bytes following "aaaa"

    if buf.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "aaaa data is too short"));
    }

    // Extract the 2 bytes for the length of Protobuf data
    let pb_data_length = u16::from_be_bytes([buf[4], buf[5]]) as usize;

    // Check if the received data is complete
    if buf.len() < 6 + pb_data_length {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "aaaa  data is too short Incomplete Protobuf data"));
    }

    // Extract the Protobuf data
    let pb_data = &buf[6..(6 + pb_data_length)];

    // Deserialize the Protobuf data
    let pb_message = PasswordResponse::parse_from_bytes(pb_data);

    // Handle the deserialized message as needed
    match pb_message {
        Ok(deserialized_message) => {
            Ok(deserialized_message)
        }
        Err(_) => {
            // Handle deserialization error
            Err(io::Error::new(io::ErrorKind::InvalidData, "Protobuf deserialization error from PasswordResponse"))
        }
    }
}