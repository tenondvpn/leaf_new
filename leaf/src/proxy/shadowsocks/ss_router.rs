use bytes::{BufMut, BytesMut};
use lazy_static::lazy_static;
use openssl::sha::Sha256;
use std::sync::Mutex;
use tokio::io;
use tokio::io::ReadBuf;

const SYS_ROUT_FLAG: &[u8; 4] = b"aaaa";
const SYS_ROUT_FLAG_LEN: usize = SYS_ROUT_FLAG.len();
const ROUT_DATA_LEN: usize = 2;
const ROUT_HEADER_LEN: usize = SYS_ROUT_FLAG_LEN + ROUT_DATA_LEN;

const PROTOCOL_HASH_LEN: usize = 2;

lazy_static! {
    static ref GLOBAL_ROUTES_DATA: Mutex<String> = Mutex::new(String::new());
}

pub fn consume_and_refresh_routes(buf: &mut ReadBuf) {
    match consume_rout_data_from_buf(buf) {
        Ok(Some(data)) => {
            refresh_routes(data);
            println!("Read data successfully");
        }
        Ok(None) => {}
        Err(err) => println!("Read data failed: {}", err),
    }
}

pub fn get_routes_hash_head() -> BytesMut {
    let hash = generate_routes_hash();
    let mut hash_data = BytesMut::new();
    hash_data.put_u16(hash.len() as u16);
    hash_data.put_slice(&hash);
    hash_data
}

pub fn get_route_data() -> String {
    GLOBAL_ROUTES_DATA.lock().unwrap().clone()
}

// 提取 rout 信息 并消费buffer
fn consume_rout_data_from_buf(buf: &mut ReadBuf) -> io::Result<Option<String>> {
    if buf.filled().len() < SYS_ROUT_FLAG_LEN + ROUT_DATA_LEN {
        // Not enough data to make a decision, return as is.
        return Ok(None);
    }
    // Get the first 4 bytes from the buffer.
    let prefix = &buf.filled()[..SYS_ROUT_FLAG_LEN];
    if prefix != SYS_ROUT_FLAG {
        return Ok(None);
    }

    // Read the length as a u16 from the next 2 bytes.
    let length = u16::from_be_bytes([buf.filled()[4], buf.filled()[5]]);

    if buf.filled().len() < ROUT_HEADER_LEN + length as usize {
        // Not enough data to read the complete string, return as is.
        return Ok(None);
    }

    // Convert the bytes to a String.
    let rout_byte_data = &buf.filled()[ROUT_HEADER_LEN..ROUT_HEADER_LEN + length as usize];
    let rout_string_value = String::from_utf8_lossy(rout_byte_data).to_string();

    // remove rout data
    let new_buf = &buf.filled()[ROUT_HEADER_LEN + length as usize..].to_owned();
    buf.clear();
    buf.put_slice(&new_buf);

    return Ok(Some(rout_string_value));
}

fn generate_routes_hash() -> BytesMut {
    let route = {
        let cur_routes = GLOBAL_ROUTES_DATA.lock().unwrap();
        cur_routes.clone()
    };

    let mut hasher = Sha256::new();
    hasher.update(route.as_bytes());
    let hash = hasher.finish();
    let mut buffer = BytesMut::new();
    buffer.put_slice(&hash[..]);
    buffer
}

// 更新全局变量
fn refresh_routes(routes: String) {
    let mut old_routes = GLOBAL_ROUTES_DATA.lock().unwrap();
    old_routes.clear();
    old_routes.push_str(&routes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_buf_valid_prefix() -> io::Result<()> {
        let strs = &mut [0u8; 40][..];

        let mut buf = ReadBuf::new(strs);
        buf.put_slice(b"aaaa".as_ref());
        buf.put_slice(&(9u16.to_be_bytes())[..]);
        buf.put_slice(b"12345678910111213");

        let result = consume_rout_data_from_buf(&mut buf)?;

        assert_eq!(result, Some("123456789".to_string()));
        Ok(())
    }

    #[test]
    fn test_process_buf_invalid_prefix() -> io::Result<()> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"notahello");

        let mut buffer = ReadBuf::new(&mut data);
        let result = consume_rout_data_from_buf(&mut buffer)?;

        assert_eq!(result, None);
        Ok(())
    }
}
