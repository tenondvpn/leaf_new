use std::collections::HashMap;
use std::sync::Mutex;

use bytes::{BufMut, BytesMut};
use lazy_static::lazy_static;
use log::{debug, error};
use protobuf::Message;
use tokio::io;
use crate::common::error_queue::push_error;

use crate::proto::server_config::{PasswordResponse, Route};

const SYS_ROUT_FLAG: &[u8; 4] = b"aaaa";
const SYS_ROUT_FLAG_LEN: usize = SYS_ROUT_FLAG.len();
const ROUT_DATA_LEN: usize = 2;
const ROUT_HEADER_LEN: usize = SYS_ROUT_FLAG_LEN + ROUT_DATA_LEN;

const PROTOCOL_HASH_LEN: usize = 2;

lazy_static! {
    static ref GLOBAL_ROUTES_DATA: Mutex<Route> = Mutex::new(Route::new());
    // key = ip_port
    static ref PROXY_NODE_MAP: Mutex<HashMap<String, (u64, Vec<u8>)>> = Mutex::new(HashMap::new());
}

pub fn sec_cache_refresh(addr: &str, port: u32, sec: (u64, Vec<u8>)) {
    let key = format_to_key(addr, port);
    if let Ok(mut map) = PROXY_NODE_MAP.lock() {
        map.insert(key, sec);
    } else {
        error!("error: refresh proxy   key:{:?}, value:{:?}", key, sec);
    }
}

pub fn get_sec_from_cache(addr: &str, port: u32) -> Option<(u64, Vec<u8>)> {
    let key = format_to_key(addr, port);

    if let Ok(map) = PROXY_NODE_MAP.lock() {
        if let Some(node) = map.get(&key) {
            return Some(node.clone());
        }
    } else {
        error!("error: get_proxy_node_uid  key:{:?}", key);
    }
    None
}

fn format_to_key(addr: &str, port: u32) -> String {
    format!("{}:{}", addr, port)
}

pub fn check_special_tag_in_stream(buf: &mut BytesMut) -> bool {
    match get_rout_data_from_buf(buf) {
        Ok(Some(data)) => {
            let msg = format!("consume_rout_data_from_buf aaaa response_data {:?}", data);
            push_error();
            panic!("{msg}");
        }
        Ok(None) => false,
        Err(err) => {
            error!("Read data failed: {}", err);
            false
        }
    }
}

pub fn get_route_data() -> String {
    GLOBAL_ROUTES_DATA
        .lock()
        .unwrap()
        .get_route()
        .to_string()
        .clone()
}

// 提取 rout 信息 并消费buffer
fn get_rout_data_from_buf(buf: &mut BytesMut) -> io::Result<Option<PasswordResponse>> {
    if buf.len() < SYS_ROUT_FLAG_LEN + ROUT_DATA_LEN {
        debug!(
            "consume_rout_data_from_buf Not enough data len {}",
            buf.len()
        );
        // Not enough data to make a decision, return as is.
        return Ok(None);
    }
    // Get the first 4 bytes from the buffer.
    let prefix = &buf[..SYS_ROUT_FLAG_LEN];
    debug!(
        "consume_rout_data_from_buf  Get the first 4 bytes {:?}",
        prefix
    );
    if prefix != SYS_ROUT_FLAG {
        return Ok(None);
    }

    // Read the length as a u16 from the next 2 bytes.
    let length = u16::from_be_bytes([buf[SYS_ROUT_FLAG_LEN], buf[SYS_ROUT_FLAG_LEN + 1]]);

    if buf.len() < ROUT_HEADER_LEN + length as usize {
        // Not enough data to read the complete string, return as is.
        return Ok(None);
    }

    // Convert the bytes to a String.
    let rout_byte_data = &buf[ROUT_HEADER_LEN..ROUT_HEADER_LEN + length as usize];
    // let rout_string_value = String::from_utf8_lossy(rout_byte_data).to_string();

    let route_pb = PasswordResponse::parse_from_bytes(rout_byte_data).expect("parse rout protobuf error");

    return Ok(Some(route_pb));
}

pub fn generate_routes_hash() -> BytesMut {
    debug!("获取锁");
    let route_hash = {
        let route = GLOBAL_ROUTES_DATA.lock().unwrap();
        debug!("释放锁");
        route.get_route_hash().to_vec()
    };

    let mut buffer = BytesMut::from(route_hash.as_slice());
    buffer
}

// 更新全局变量
fn refresh_routes(routes: Route) {
    let mut old_routes = GLOBAL_ROUTES_DATA.lock().unwrap();
    old_routes.set_route(routes.get_route().to_string());
    old_routes.set_route_hash(routes.get_route_hash().to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_buf_valid_prefix() -> io::Result<()> {
        println!("aa : {}", "aa");

        Ok(())
    }

    #[test]
    pub fn test_refresh_routes() {
        use super::*;
        let mut route = Route::new();
        route.set_route("test".to_string());
        route.set_route_hash("test".as_bytes().to_vec());
        refresh_routes(route);
        println!("route data is : {}", get_route_data());

        let hash = generate_routes_hash();
        println!("hash : {:?}", &hash);
    }
}
