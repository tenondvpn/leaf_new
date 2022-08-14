use std::io;
extern crate rand;
use rand::Rng;
use async_trait::async_trait;

use tokio::io::AsyncWriteExt;
use bytes::{BufMut, Bytes, BytesMut};

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
        let tmp_route = tmp_vec[1].to_string();
        let route_vec: Vec<&str> = tmp_route.split("-").collect();
        let mut rng = rand::thread_rng();
        let rand_idx = rng.gen_range(0..route_vec.len());
        let ip_port = route_vec[rand_idx].to_string();
        let ip_port_vec: Vec<&str> = ip_port.split("N").collect();
        let address = ip_port_vec[0].to_string();
        let port: u16 = ip_port_vec[1].parse::<u16>().unwrap();

        Some(OutboundConnect::Proxy(address.clone(), port))
        //Some(OutboundConnect::Proxy(self.address.clone(), self.port))
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
        let vpn_ip = vec[1].parse::<u32>().unwrap();
        let vpn_port = vec[2].parse::<u16>().unwrap();
        let pk_str = vec[3].to_string();
        let ver = vec[4].to_string();

        let mut buffer1 = BytesMut::with_capacity(92);
        buffer1.put_u32(vpn_ip);
        buffer1.put_u16(vpn_port);
        let pk_str = String::from(pk_str.clone());
        buffer1.put_slice(pk_str[..].as_bytes());
        buffer1.put_u8(19);
        let ver_str = String::from(ver.clone());
        buffer1.put_slice(ver_str[..].as_bytes());
        src_stream.write_all(&buffer1).await?;

        let mut stream = ShadowedStream::new(src_stream, &self.cipher, &tmp_ps)?;
        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast);
        stream.write_all(&buf).await?;
        Ok(Box::new(stream))
    }
}
