use std::io;
extern crate rand;
use std::net::Ipv4Addr;
use rand::Rng;
use rand::thread_rng;
use rand::distributions::Alphanumeric;
use async_trait::async_trait;
use crate::common;
use tokio::io::AsyncWriteExt;
use bytes::{BufMut, Bytes, BytesMut};
use openssl::sha::Sha256;
use super::shadow::ShadowedStream;
use crate::{
    proxy::*,
    session::{Session, SocksAddrWireType},
};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
}

#[async_trait]
impl TcpOutboundHandler for Handler {
    type Stream = AnyStream;

    fn connect_addr(&self) -> Option<OutboundConnect> {
        let tmp_vec: Vec<&str> = self.password.split("M").collect();
        let tmp_pass = tmp_vec[0].to_string();
        let vec :Vec<&str> = tmp_pass.split("-").collect();
        let mut address = "".to_string();
        let mut port: u16 = 0;
        if (vec.len() >= 8 && vec[7].parse::<u32>().unwrap() != 0) {
            address = vec[1].to_string();
            port = vec[2].parse::<u16>().unwrap();
        } else {
            let test_str = common::sync_valid_routes::GetValidRoutes();
            let route_vec: Vec<&str> = test_str.split(",").collect();
            if (route_vec.len() >= 2) {
                let mut rng = rand::thread_rng();
                let rand_idx = rng.gen_range(0..route_vec.len());
                let ip_port = route_vec[rand_idx].to_string();
                let ip_port_vec: Vec<&str> = ip_port.split(":").collect();
                if (ip_port_vec.len() >= 2) {
                    address = ip_port_vec[0].to_string();
                    port = ip_port_vec[1].parse::<u16>().unwrap();
                }
            }

            if (port == 0) {
                let tmp_route = tmp_vec[1].to_string();
                let route_vec: Vec<&str> = tmp_route.split("-").collect();
                let mut rng = rand::thread_rng();
                let rand_idx = rng.gen_range(0..route_vec.len());
                let ip_port = route_vec[rand_idx].to_string();
                let ip_port_vec: Vec<&str> = ip_port.split("N").collect();
                address = ip_port_vec[0].to_string();
                port = ip_port_vec[1].parse::<u16>().unwrap();
            }
        }

        Some(OutboundConnect::Proxy(address.clone(), port))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        let mut src_stream = stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
        let tmp_vec: Vec<&str> = self.password.split("M").collect();
        let tmp_pass = tmp_vec[0].to_string();
        let vec :Vec<&str> = tmp_pass.split("-").collect(); 
        let tmp_ps = vec[0].to_string();
        let ver = vec[4].to_string();
        let mut pk_len = vec[3].len() as u32;
        if (pk_len > 66) {
            pk_len = pk_len / 2;
        }

        pk_len += 2;
        let n2: u8 = thread_rng().gen_range(7..16);
        let rand_len = n2 as u32;
        let mut all_len = 26 + rand_len + 1 + pk_len;
        if (vec.len() >= 8 && vec[7].parse::<u32>().unwrap() != 0) {
            all_len -= 6;
        }

        let mut buffer1 = BytesMut::with_capacity(all_len as usize);

        let mut head_size = 0;
        if (vec.len() >= 8) {
            if (vec[7].parse::<u32>().unwrap() == 0) {
                let ex_r_ip = vec[5].parse::<u32>().unwrap();
                if (ex_r_ip != 0) {
                    let test_str = common::sync_valid_routes::GetValidRoutes();
                    let route_vec: Vec<&str> = test_str.split(",").collect();
                    if (route_vec.len() >= 2) {
                        let mut rng = rand::thread_rng();
                        let rand_idx = rng.gen_range(0..route_vec.len());
                        let ip_port = route_vec[rand_idx].to_string();
                        let ip_port_vec: Vec<&str> = ip_port.split(":").collect();
                        if (ip_port_vec.len() >= 2) {
                            let tmp_ip = ip_port_vec[0].to_string();
                            let ip_split: Vec<&str> = tmp_ip.split(".").collect();
                            let addr = Ipv4Addr::new(
                                ip_split[0].parse::<u8>().unwrap(),
                                ip_split[1].parse::<u8>().unwrap(),
                                ip_split[2].parse::<u8>().unwrap(),
                                ip_split[3].parse::<u8>().unwrap());
                            let ip_int = addr.into();
                            let port: u16 = ip_port_vec[1].parse::<u16>().unwrap();
                            all_len += 6;
                            head_size += 6;
                            buffer1 = BytesMut::with_capacity(all_len as usize);
                            buffer1.put_u32(ip_int);
                            buffer1.put_u16(port);
                        }
                    }

                    if (head_size == 6) {
                        all_len += 6;
                        head_size += 6;
                        buffer1 = BytesMut::with_capacity(all_len as usize);
                        buffer1.put_u32(ex_r_ip);
                        buffer1.put_u16(vec[6].parse::<u16>().unwrap());
                    }
                }
            }
        }

        if (vec.len() >= 8 && vec[7].parse::<u32>().unwrap() == 0) {
            let vpn_ip = vec[1].parse::<u32>().unwrap();
            let vpn_port = vec[2].parse::<u16>().unwrap();
            buffer1.put_u32(vpn_ip);
            buffer1.put_u16(vpn_port);
            head_size += 6;
        } 

        buffer1.put_u8(n2);
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(n2 as usize)
            .map(char::from)
            .collect();
        buffer1.put_slice(rand_string[..].as_bytes());
        buffer1.put_u16(pk_len.try_into().unwrap());
        if (pk_len > 68) {
            let pk_str = hex::decode(vec[3]).expect("Decoding failed");
            let ex_hash = common::sync_valid_routes::GetResponseHash(self.address.clone());
            if (ex_hash.eq("")) {
                let mut test_str = hex::encode(pk_str.clone());
                let mut hasher = Sha256::new();
                hasher.update(&pk_str.clone());
                let result = hasher.finish();
                let result_str = hex::encode(result);
                common::sync_valid_routes::SetResponseHash(self.address.clone(), result_str);
            }
            
            buffer1.put_slice(&pk_str);
        } else {
            let pk_str = vec[3].to_string();
            let pk_str = String::from(pk_str.clone());
            buffer1.put_slice(pk_str[..].as_bytes());
        }
        
        buffer1.put_u8(19);
        let ver_str = String::from(ver.clone());
        buffer1.put_slice(ver_str[..].as_bytes());

        let mut i = 0;
        let pos: usize = head_size + (n2 as usize / 2);
        while i != buffer1.len() {
            if i == pos || i == head_size {
                i = i + 1;
                continue;
            }

            buffer1[i] = buffer1[i] ^ buffer1[pos];
            i = i + 1;
        }

        if buffer1.len() != all_len as usize {
            panic!("this is a terrible mistake!");
        }

        src_stream.write_all(&buffer1).await?;

        let mut stream = ShadowedStream::new(src_stream, &self.cipher, &tmp_ps)?;
        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast);
        stream.write_all(&buf).await?;
        Ok(Box::new(stream))
    }
}
