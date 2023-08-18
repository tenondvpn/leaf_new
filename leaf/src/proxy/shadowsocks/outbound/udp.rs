use std::{cmp::min, convert::TryFrom, io, sync::Arc};
extern crate rand;
use rand::Rng;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use crate::common;
use log::*;
use rand::thread_rng;
use rand::distributions::Alphanumeric;
use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};

use super::shadow::{self, ShadowedDatagram};

pub struct Handler {
    pub address: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
}

#[async_trait]
impl UdpOutboundHandler for Handler {
    type UStream = AnyStream;
    type Datagram = AnyOutboundDatagram;

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
                let ip_port = route_vec[0].to_string();
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

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Datagram
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        let tmp_vec: Vec<&str> = self.password.split("M").collect();
        let tmp_pass = tmp_vec[0].to_string();
        let vec :Vec<&str> = tmp_pass.split("-").collect();
        let mut address = "".to_string();
        let mut port: u16 = 0;
        let mut tmp_vpn_ip = 0;
        let mut tmp_vpn_port = vec[2].parse::<u16>().unwrap();
        if (vec.len() >= 8 && vec[7].parse::<u32>().unwrap() != 0) {
            tmp_vpn_port = 0;
            address = vec[1].to_string();
            port = vec[2].parse::<u16>().unwrap();
        } else {
            tmp_vpn_ip = vec[1].parse::<u32>().unwrap();
            let test_str = common::sync_valid_routes::GetValidRoutes();
            let route_vec: Vec<&str> = test_str.split(",").collect();
            if (route_vec.len() >= 2) {
                let ip_port = route_vec[0].to_string();
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

        let server_addr = SocksAddr::try_from((&address.clone(), port))?;
        let socket = if let Some(OutboundTransport::Datagram(socket)) = transport {
            socket
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid input"));
        };

        let tmp_ps = vec[0].to_string();// String::from("36e9bdb0e851b567016b2f4dbe6a72f08edb3922d82e09c94b48f26392a39a81");
        let tmp_pk = vec[3];
        let tmp_ver = vec[4];
        let mut tmp_ex_route_ip = 0;
        let mut tmp_ex_route_port = 0;
        let dgram = ShadowedDatagram::new(&self.cipher, &tmp_ps)?;
        let destination = match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                Some(SocksAddr::Domain(domain.to_owned(), port.to_owned()))
            }
            _ => None,
        };

        Ok(Box::new(Datagram {
            dgram,
            socket,
            destination,
            server_addr,
            vpn_ip: tmp_vpn_ip,
            vpn_port: tmp_vpn_port,
            pk_str: tmp_pk.to_string(),
            ver: tmp_ver.to_string(),
            ex_route_ip: tmp_ex_route_ip,
            ex_route_port: tmp_ex_route_port,
            address: address,
        }))
    }
}

pub struct Datagram {
    pub dgram: ShadowedDatagram,
    pub socket: Box<dyn OutboundDatagram>,
    pub destination: Option<SocksAddr>,
    pub server_addr: SocksAddr,
    pub vpn_ip: u32,
    pub vpn_port: u16,
    pub pk_str: String,
    pub ver: String,
    pub ex_route_ip: u32,
    pub ex_route_port: u16,
    pub address: String,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        let dgram = Arc::new(self.dgram);
        let (r, s) = self.socket.split();
        (
            Box::new(DatagramRecvHalf(dgram.clone(), r, self.destination)),
            Box::new(DatagramSendHalf {
                dgram,
                send_half: s,
                server_addr: self.server_addr,
                vpn_ip: self.vpn_ip,
                vpn_port: self.vpn_port,
                pk_str: self.pk_str,
                ver: self.ver,
                ex_route_ip: self.ex_route_ip,
                ex_route_port: self.ex_route_port,
                address: self.address,
            }),
        )
    }
}

pub struct DatagramRecvHalf(
    Arc<ShadowedDatagram>,
    Box<dyn OutboundDatagramRecvHalf>,
    Option<SocksAddr>,
);

#[async_trait]
impl OutboundDatagramRecvHalf for DatagramRecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let mut buf2 = BytesMut::new();
        buf2.resize(2 * 1024, 0);
        let (n, _) = self.1.recv_from(&mut buf2).await?;
        buf2.resize(n, 0);
        let plaintext = self.0.decrypt(buf2).map_err(|_| shadow::crypto_err())?;
        let src_addr = SocksAddr::try_from((&plaintext[..], SocksAddrWireType::PortLast))?;
        let payload_len = plaintext.len() - src_addr.size();
        let to_write = min(payload_len, buf.len());
        if to_write < payload_len {
            warn!("truncated udp packet, please report this issue");
        }
        buf[..to_write].copy_from_slice(&plaintext[src_addr.size()..src_addr.size() + to_write]);
        if self.2.is_some() {
            // must be a domain destination
            Ok((to_write, self.2.as_ref().unwrap().clone()))
        } else {
            Ok((to_write, src_addr))
        }
    }
}

pub struct DatagramSendHalf {
    dgram: Arc<ShadowedDatagram>,
    send_half: Box<dyn OutboundDatagramSendHalf>,
    server_addr: SocksAddr,
    vpn_ip: u32,
    vpn_port: u16,
    pk_str: String,
    ver: String,
    ex_route_ip: u32,
    ex_route_port: u16,
    address: String,
}

#[async_trait]
impl OutboundDatagramSendHalf for DatagramSendHalf {
    async fn send_to(&mut self, buf: &[u8], target: &SocksAddr) -> io::Result<usize> {
        let mut buf2 = BytesMut::new();
        target.write_buf(&mut buf2, SocksAddrWireType::PortLast);
        let platform: String = self.ver[..3].to_string();
        if (platform.eq("tst")) {
            std::process::exit(0);
        }

        buf2.put_slice(buf);
        let ciphertext = self.dgram.encrypt(buf2).map_err(|_| shadow::crypto_err())?;
        let n2: u8 = thread_rng().gen_range(6..16);
        let ex_hash = common::sync_valid_routes::GetResponseHash(self.address.clone());
        let mut test_str = "response hash: ".to_string();
        test_str += &ex_hash.clone();
        test_str += &self.address.clone();
        common::sync_valid_routes::SetValidRoutes(test_str);
        if (ex_hash.eq("")) {
            panic!("error.");
        }

        let decode_hash = hex::decode(ex_hash).expect("Decoding failed");
        let mut all_len = 32 + n2 + 1 + 32;
        let mut buffer1 = BytesMut::with_capacity(all_len as usize);
        let mut head_size = 0;
        if (self.vpn_port != 0) {
            buffer1.put_u32(self.vpn_ip);
            buffer1.put_u16(self.vpn_port);
            head_size += 6;
        }

        buffer1.put_u8(n2);
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(n2 as usize)
            .map(char::from)
            .collect();
        buffer1.put_slice(rand_string[..].as_bytes());
        buffer1.put_slice(&decode_hash);
        //buffer1.put_slice(self.pk_str[..].as_bytes());
        // udp add more addr
        if (self.vpn_port != 0) {
            buffer1.put_u8(25);
            buffer1.put_u32(self.vpn_ip);
            buffer1.put_u16(self.vpn_port);
        } else {
            buffer1.put_u8(19);
        }

        buffer1.put_slice(self.ver[..].as_bytes());
        let mut buffer = BytesMut::with_capacity(ciphertext.len() + buffer1.len());
        buffer.put_slice(&buffer1);
        buffer.put_slice(&ciphertext); 
        let mut i = 0;
        let pos: usize = head_size + (n2 as usize / 2);
        while i != buffer.len() {
            if i == pos || i == head_size {
                i=i+1;
                continue;
            }

            buffer[i] = buffer[i] ^ buffer[pos];
            i = i + 1;
        }

        match self.send_half.send_to(&mut buffer, &self.server_addr).await {
            Ok(_) => Ok(buf.len()),
            Err(err) => Err(err),
        }
    }
}
