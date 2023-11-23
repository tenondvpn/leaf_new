use std::{cmp::min, convert::TryFrom, io, sync::Arc};
use std::num::ParseIntError;

extern crate rand;
use crate::common;
use crate::{
    proxy::*,
    session::{Session, SocksAddr, SocksAddrWireType},
};
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use futures_util::AsyncReadExt;
use log::*;
use protobuf::Message;
use rand::distributions::Alphanumeric;
use rand::thread_rng;
use rand::Rng;
use crate::common::error_queue::push_error;
use crate::common::sync_valid_routes::{get_random_password_from_map, password_map_get};
use crate::proto::client_config::ClientNode;
use crate::proto::client_config::ErrorType::change_password_error;
use crate::proto::server_config::{EncMethodEnum, GlobalConfig, PasswordResponse};
use crate::proxy::shadowsocks::convert_from_with_error_tag;

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
        trace!("handle udp addr");

        let (addr,port) =  match get_random_password_from_map() {
            None => {
                let msg = format!("Proxy address is invalid");
                push_error(change_password_error, "".to_string());
                return None;
            }
            Some(a) => {(a.get_server_address().to_string(), a.get_server_port().clone())}
        };

        Some(OutboundConnect::Proxy(addr, port as u16))
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Datagram
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        transport: Option<OutboundTransport<Self::UStream, Self::Datagram>>,
    ) -> io::Result<Self::Datagram> {
        trace!("handle udp stream");

        let proxy_node =  match get_random_password_from_map() {
            None => {
                let msg = format!("Proxy address is invalid");
                push_error(change_password_error, "".to_string());
                return  Err(io::Error::new(io::ErrorKind::Other, format!("Proxy address is invalid: ")));
            }
            Some(a) => a,
        };

        let (address, port) = (proxy_node.get_server_address(), proxy_node.get_server_port() as u16);
        let server_addr = SocksAddr::try_from((&address.to_string(), (port as u16)))?;
        let socket = if let Some(OutboundTransport::Datagram(socket)) = transport {
            socket
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid input"));
        };

        let tmp_ps = proxy_node.get_symmetric_crypto_info().get_sec_key(); // String::from("36e9bdb0e851b567016b2f4dbe6a72f08edb3922d82e09c94b48f26392a39a81");
        let tmp_pk = proxy_node.get_asymmetric_crypto_info().get_server_pubkey();
        let tmp_ver =  "";
        let mut tmp_ex_route_ip = 0;
        let mut tmp_ex_route_port = 0;
        let dgram = ShadowedDatagram::new(&self.cipher, tmp_ps)?;
        let destination = match &sess.destination {
            SocksAddr::Domain(domain, port) => {
                Some(SocksAddr::Domain(domain.to_owned(), port.to_owned()))
            }
            _ => None,
        };

        // let vpn_ip = match  address.parse::<u32>() {
        //     Ok(a) => {a}
        //     Err(b) => {
        //         error!{"{:?}", b};
        //         return Err(io::Error::new(io::ErrorKind::Other, "invalid input"));
        //     }
        // };
        Ok(Box::new(Datagram {
            dgram,
            socket,
            destination,
            server_addr,
            vpn_ip: 0,
            vpn_port: port as u16,
            pk_str: tmp_pk.to_string(),
            ver: tmp_ver.to_string(),
            ex_route_ip: tmp_ex_route_ip,
            ex_route_port: tmp_ex_route_port,
            address: address.to_string(),
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

        #[cfg(any(test, debug_assertions))]
        trace!("udp receive from address {:?}", &src_addr);

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

        let proxy_node = match password_map_get(self.address.as_str(), self.vpn_port as u32) {
            None => {
                let msg = format!("Proxy address is invalid");
                push_error(change_password_error, "send_to error".to_string());
                return Err(io::Error::new(io::ErrorKind::Other, "send_to error"));
            }
            Some(a) => a
        };
        let enc_type = proxy_node.get_symmetric_crypto_info().get_enc_method_type().clone();
        let need_enc = enc_type == EncMethodEnum::NO_ENC;
        let mut global_config = GlobalConfig::default();
        global_config.set_current_message_encrypted(need_enc);
        global_config.set_symmetric_cryptograph_type(enc_type);

        let symmetric_crypto_info = proxy_node.get_symmetric_crypto_info();
        let uid = symmetric_crypto_info.get_client_unique_id();
        global_config.set_client_unique_id(uid);

        let pb = &global_config.write_to_bytes().unwrap();
        let mut plain_buf = BytesMut::new();
        plain_buf.put_u16(pb.len() as u16);
        plain_buf.put_slice(pb.as_slice());


        let mut buf2 = BytesMut::new();
        target.write_buf(&mut buf2, SocksAddrWireType::PortLast);
        buf2.put_slice(buf);
        let ciphertext = self.dgram.encrypt(buf2).map_err(|_| shadow::crypto_err())?;


        let mut buffer = BytesMut::with_capacity(ciphertext.len() + plain_buf.len());
        buffer.put_slice(&plain_buf);
        buffer.put_slice(&ciphertext);

        #[cfg(any(test, debug_assertions))]
        trace!("global {:?} ,ciphertext:{:?} , allbuffer:{:?}", &global_config, hex::encode(&ciphertext), hex::encode(&buffer));

        match self.send_half.send_to(&mut buffer, &self.server_addr).await {
            Ok(_) => Ok(buf.len()),
            Err(err) => Err(err),
        }
    }
}
