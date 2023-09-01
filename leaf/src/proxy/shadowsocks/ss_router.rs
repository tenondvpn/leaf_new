use std::sync::Mutex;

use bytes::{BufMut, BytesMut};
use lazy_static::lazy_static;
use log::{debug, error};
use protobuf::Message;
use tokio::io;

use crate::proto::server_config::Route;

const SYS_ROUT_FLAG: &[u8; 4] = b"aaaa";
const SYS_ROUT_FLAG_LEN: usize = SYS_ROUT_FLAG.len();
const ROUT_DATA_LEN: usize = 2;
const ROUT_HEADER_LEN: usize = SYS_ROUT_FLAG_LEN + ROUT_DATA_LEN;

const PROTOCOL_HASH_LEN: usize = 2;

lazy_static! {
    static ref GLOBAL_ROUTES_DATA: Mutex<Route> = Mutex::new(Route::new());
}

pub fn check_and_refresh_routes(buf: &mut BytesMut) -> bool {
    match get_rout_data_from_buf(buf) {
        Ok(Some(data)) => {
            debug!("consume_rout_data_from_buf route_pb {:?}", data);
            refresh_routes(data);
            debug!("after refresh_routes :{:?}", {GLOBAL_ROUTES_DATA.lock().unwrap()});
            true
        }
        Ok(None) => { false }
        Err(err) => {
            error!("Read data failed: {}", err);
            false
        },
    }
}


pub fn get_route_data() -> String {
    GLOBAL_ROUTES_DATA.lock().unwrap()
        .get_route().to_string().clone()
}

// 提取 rout 信息 并消费buffer
fn get_rout_data_from_buf(buf:  &mut BytesMut) -> io::Result<Option<Route>> {
    if buf.len() < SYS_ROUT_FLAG_LEN + ROUT_DATA_LEN {
        debug!("consume_rout_data_from_buf Not enough data len {}", buf.len());
        // Not enough data to make a decision, return as is.
        return Ok(None);
    }
    // Get the first 4 bytes from the buffer.
    let prefix = &buf[..SYS_ROUT_FLAG_LEN];
    debug!("consume_rout_data_from_buf  Get the first 4 bytes {:?}", prefix);
    if prefix != SYS_ROUT_FLAG {
        return Ok(None);
    }

    // Read the length as a u16 from the next 2 bytes.
    let length = u16::from_be_bytes([buf[SYS_ROUT_FLAG_LEN], buf[SYS_ROUT_FLAG_LEN+1]]);

    if buf.len() < ROUT_HEADER_LEN + length as usize {
        // Not enough data to read the complete string, return as is.
        return Ok(None);
    }

    // Convert the bytes to a String.
    let rout_byte_data = &buf[ROUT_HEADER_LEN..ROUT_HEADER_LEN + length as usize];
    // let rout_string_value = String::from_utf8_lossy(rout_byte_data).to_string();

    let route_pb = Route::parse_from_bytes(rout_byte_data)
        .expect("parse rout protobuf error");

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
        println!("aa : {}","aa");

        Ok(())
    }

    #[test]
    pub  fn test_refresh_routes() {
        use super::*;
        let mut route = Route::new();
        route.set_route("test".to_string());
        route.set_route_hash("test".as_bytes().to_vec());
        refresh_routes(route);
        println!("route data is : {}",  get_route_data());

        let hash = generate_routes_hash();
        println!("hash : {:?}", &hash);


    }
}

