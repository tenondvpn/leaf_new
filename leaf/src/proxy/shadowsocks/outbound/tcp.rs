extern crate rand;

use std::error::Error;
use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use openssl::sha::Sha256;
use protobuf::Message;
use rand::Rng;
use tokio::io::AsyncWriteExt;

use crate::{common, proto};
use crate::{
    proxy::*,
    session::{Session, SocksAddrWireType},
};
use crate::proto::server_config::ServerConfig;
use crate::proxy::shadowsocks::ss_router::generate_routes_hash;

use super::shadow::ShadowedStream;

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
        let vec: Vec<&str> = tmp_pass.split("-").collect();
        let mut address = "".to_string();
        let mut port: u16 = 0;
        if vec.len() >= 8 && vec[7].parse::<u32>().unwrap() != 0 {
            address = vec[1].to_string();
            port = vec[2].parse::<u16>().unwrap();
        } else {
            let test_str = common::sync_valid_routes::GetValidRoutes();
            let route_vec: Vec<&str> = test_str.split(",").collect();
            if route_vec.len() >= 2 {
                let mut rng = rand::thread_rng();
                let rand_idx = rng.gen_range(0..route_vec.len());
                let ip_port = route_vec[rand_idx].to_string();
                let ip_port_vec: Vec<&str> = ip_port.split(":").collect();
                if ip_port_vec.len() >= 2 {
                    address = ip_port_vec[0].to_string();
                    port = ip_port_vec[1].parse::<u16>().unwrap();
                }
            }

            if port == 0 {
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
        let mut src_stream =
            stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;
        let tmp_vec: Vec<&str> = self.password.split("M").collect();
        let tmp_pass = tmp_vec[0].to_string();
        let vec: Vec<&str> = tmp_pass.split("-").collect();
        let tmp_ps = vec[0].to_string();
        let mut address = self.address.clone();
        if vec.len() >= 8 && vec[7].parse::<u32>().unwrap() != 0 {
            address = vec[1].to_string();
        }

        let ver = vec[4].to_string();
        let mut pk_len = vec[3].len() as u32;
        if pk_len > 66 {
            pk_len = pk_len / 2;
        }
        pk_len += 2;

        let mut pk_str;
        if pk_len > 68 {
            pk_str = hex::decode(vec[3]).expect("Decoding failed");
            let ex_hash = common::sync_valid_routes::GetResponseHash(address.clone());
            if ex_hash.eq("") {
                let _test_str = hex::encode(pk_str.clone());
                let mut hasher = Sha256::new();
                hasher.update(&pk_str.clone());
                let result = hasher.finish();
                let result_str = hex::encode(result);
                let mut test_hash = "set hash: ".to_string();
                test_hash += &address.clone();
                test_hash += &result_str.clone();
                common::sync_valid_routes::SetValidRoutes(test_hash);
                common::sync_valid_routes::SetResponseHash(address.clone(), result_str);
            }
        } else {
            pk_str = vec[3].as_bytes().to_vec();
        }
        debug!("开始");

        let server_conf_prof = match Self::build_server_conf(ver, pk_str) {
            Ok(server_config) => {
                // Handle success
                server_config
            }
            Err(error) => {
                // Handle error
                println!("Error: {:?}", error);
                ServerConfig::new()
            }
        };
        debug!("sever_conf_prof:{:?}", server_conf_prof);
        let pb = server_conf_prof.write_to_bytes().unwrap();
        let mut buffer = BytesMut::new();
        buffer.put_u16(pb.len() as u16);
        buffer.put_slice(pb.as_slice());
        debug!("write_server_conf:{:?}", buffer.to_vec());
        src_stream.write_all(&buffer).await?;
        debug!("结束");

        let mut stream = ShadowedStream::new(src_stream, &self.cipher, &tmp_ps)?;
        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast);

        stream.write_all(&buf).await?;
        Ok(Box::new(stream))
    }
}

impl Handler {

    pub fn build_server_conf(ver: String, pk_str: Vec<u8>) -> Result<ServerConfig, Box<dyn Error>> {

        let mut server_conf_prof = proto::server_config::ServerConfig::new();

        server_conf_prof.set_pubkey(pk_str);
        debug!("generate_routes_hash start");
        let route_hash = generate_routes_hash();
        debug!("generate_routes_hash end");

        server_conf_prof.set_route_hash(route_hash.to_vec());

        let ver_str = String::from(ver.clone());
        let version_data: Vec<&str> = ver_str.split("_").collect();

        if version_data.len() == 3 {
            server_conf_prof.set_client_platform_type(version_data[0].to_owned());
            server_conf_prof.set_client_platform_version(version_data[1].to_owned());
            server_conf_prof.set_client_platform_category(version_data[2].to_owned());
        } else {
            error!("set_client_platform_version error: {}", ver_str);
        }
        Ok(server_conf_prof)
    }
}