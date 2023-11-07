extern crate rand;

use std::error::Error;
use std::io;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use openssl::sha::Sha256;
use protobuf::Message;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use third::zj_gm::sm::asymmetric_encrypt_SM2;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use url::quirks::password;

use super::shadow::ShadowedStream;
use crate::common;
use crate::proto::server_config::{
    ClientUIDStatusRes, EncMethodEnum, GlobalConfig, ServerConfig, UidStatusEnum,
};
use crate::proxy::shadowsocks::ss_router::{
    generate_routes_hash, get_sec_from_cache, sec_cache_refresh,
};
use crate::{
    proxy::*,
    session::{Session, SocksAddrWireType},
};
use crate::common::error_queue::push_error;
use crate::common::sync_valid_routes::{get_random_password_from_map, password_map_get};
use crate::proto::client_config::{ClientNode, ProxyNode};

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
        trace!("connect tcp addr");

        let (addr,port) =  match get_random_password_from_map() {
             None => {
                 let msg = format!("Proxy address is invalid");
                 push_error();
                 error!("Proxy address is invalid");
                 ("10.101.20.31".to_string(), 19802)
             }
             Some(a) => {(a.get_server_address().to_string(), a.get_server_port().clone())}
         };
        debug!("Proxy address is address: {}:{}", &addr,&port);

        Some(OutboundConnect::Proxy(addr, port as u16))
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        stream: Option<Self::Stream>,
    ) -> io::Result<Self::Stream> {
        trace!("handle tcp stream");
        let mut src_stream =
            stream.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid input"))?;

        let mut addr = "".to_owned();
        let mut port = 0u16;
        {

            (addr, port) = sess.proxy_addr.clone()
                .ok_or_else(|| {
                    let msg = format!("Proxy address is invalid");
                    push_error();
                    panic!("{}", msg);
                })
                .unwrap();
        }
        let proxy_node = match password_map_get(addr.as_str(), port as u32) {
            None => {
                let msg = format!("Proxy address is invalid");
                push_error();
                panic!("{}", msg);
            }
            Some(a) => a
        };

        let enc_type = proxy_node.get_symmetric_crypto_info().get_enc_method_type().clone();
        let need_enc = enc_type != EncMethodEnum::NO_ENC;
        let mut global_config = GlobalConfig::default();
        global_config.set_current_message_encrypted(need_enc);
        global_config.set_symmetric_cryptograph_type(enc_type);

        global_config.set_client_unique_id(15720307825053696);
        let password ="e5879349331f472e5344363aecf65b98cdea812e4be1ea1b5d69dd1ef4006358";
            // hex::decode("3ae2318f26a20a142d231b618a139ea17ae38b558071b9a4b16fab14c53973f19884e0ba3b495747fdccd32a88c6720e")
            //     .unwrap();
        // let (global_config, password)  = if need_enc {
        //     let symmetric_crypto_info = proxy_node.get_symmetric_crypto_info();
        //     let uid = symmetric_crypto_info.get_client_unique_id();
        //     let password = symmetric_crypto_info.get_sec_key();
        //     global_config.set_client_unique_id(uid);
        //
        //     (global_config, password)
        // }   else {
        //     (global_config, [0u8;0].as_slice())
        // };

        let pb = &global_config.write_to_bytes().unwrap();
        let mut buffer = BytesMut::new();
        buffer.put_u16(pb.len() as u16);
        buffer.put_slice(pb.as_slice());
        trace!("send fist global_config :{:?}, pb.len:{:?}, pb.hex:{:?}", &global_config,pb.len(),  hex::encode(pb.as_slice()));
        src_stream.write_all(&buffer).await?; // 注意这里是明文


        let mut buf = BytesMut::new();
        sess.destination
            .write_buf(&mut buf, SocksAddrWireType::PortLast);

        // trace!("sm4 sec :{}, uid:{}", hex::encode(&password.as_slice()).as_str(), &global_config.get_client_unique_id());

        if need_enc {
            let mut stream = ShadowedStream::new(src_stream, &self.cipher, password.as_bytes())?;
            stream.write_all(&buf).await?;
            Ok(Box::new(stream))
        } else {
            src_stream.write_all(&buf).await?;
            Ok(src_stream)
        }
    }
}

impl Handler {
    // async fn exchange_password(
    //     &self,
    //     src_stream: &mut AnyStream,
    //     ver: String,
    //     pk_str: Vec<u8>,
    //     addr: &String,
    //     port: u32,
    // ) -> io::Result<Vec<u8>> {
    //     let (mut uid, mut sec) = match get_sec_from_cache(addr, port) {
    //         None => (0, Vec::new()),
    //         Some(a) => a,
    //     };
    //
    //     let mut uid_status = UidStatusEnum::NOT_VALID;
    //     let mut retries = 0;
    //
    //     while uid_status != UidStatusEnum::ERROR && uid_status != UidStatusEnum::VALID {
    //         if retries >= 4 {
    //             // 重试次数已达上限
    //             error!("Max retries reached");
    //             panic!("Max retries reached");
    //         }
    //         if uid == 0 {
    //             uid_status = UidStatusEnum::NOT_VALID;
    //         }
    //
    //         match uid_status {
    //             UidStatusEnum::NOT_READY => {
    //                 trace!("uid not ready try check_uid {}, {} times", uid, retries);
    //                 uid_status = Self::check_uid(uid, src_stream).await;
    //             }
    //             UidStatusEnum::NOT_VALID => {
    //                 trace!("uid not NOT_VALID try handler {}, {:?} times", ver, &pk_str);
    //                 let (global_conf, n_sec) =
    //                     Self::build_global_conf(ver.as_str(), &pk_str, &self.cipher, "sm2")
    //                         .unwrap_or_else(|error| {
    //                             // 处理错误
    //                             error!("Error: {:?}", error);
    //                             (GlobalConfig::new(), Vec::new())
    //                         });
    //                 uid = Self::call_tcp_by_proto::<ClientUIDStatusRes>(&global_conf, src_stream)
    //                     .await?
    //                     .get_client_unique_id();
    //                 sec = n_sec;
    //             }
    //             _ => {}
    //         }
    //         // 等待指定的时间间隔
    //         let delay = match retries {
    //             0 => Duration::from_millis(200),
    //             1 => Duration::from_millis(400),
    //             2 => Duration::from_secs(1),
    //             3 => Duration::from_secs(2),
    //             4 => Duration::from_secs(5),
    //             _ => unreachable!(),
    //         };
    //         retries += 1;
    //         sleep(delay).await;
    //     }
    //
    //     // 处理最终的 uid_status
    //     match uid_status {
    //         UidStatusEnum::VALID => {
    //             sec_cache_refresh(addr, port, (uid, sec.to_vec()));
    //             trace!("uid {} is VALID", uid);
    //             Ok(sec)
    //         }
    //         UidStatusEnum::ERROR => {
    //             panic!("Uid check returned an error");
    //         }
    //         _ => {
    //             panic!("Uid is not valid");
    //         }
    //     }
    // }

    // fn build_global_conf(
    //     ver: &str,
    //     pk_str: &Vec<u8>,
    //     cipher_name: &str,
    //     handler_cipher_name: &str,
    // ) -> Result<(GlobalConfig, Vec<u8>), Box<dyn Error>> {
    //     let method_enum =
    //         EncMethodEnum::get_enum_from_string(cipher_name).expect("Cipher name not found");
    //     let handler_cipher = EncMethodEnum::get_enum_from_string(handler_cipher_name)
    //         .expect("Cipher name not found");
    //
    //     let server_config = Self::build_server_conf(ver, pk_str, method_enum);
    //     let sec = server_config.get_random_content().clone().to_vec();
    //
    //     let server_conf_bin = server_config.write_to_bytes().unwrap();
    //     let pk: Vec<i8> = pk_str.iter().map(|&byte| byte as i8).collect();
    //
    //     trace!("Before  SM2 server_config: {:?}", &server_config);
    //     // todo: in the future we need use method_enum to handle encrypt method
    //     let encrypt_content = asymmetric_encrypt_SM2(server_conf_bin.as_slice(), pk.as_slice());
    //     trace!("After  SM2 server_config: {:?}", hex::encode(&encrypt_content));
    //
    //     let route_hash = generate_routes_hash();
    //     let mut global_config = GlobalConfig::new();
    //     global_config.set_route_hash(route_hash.to_vec());
    //     global_config.set_current_message_encrypted(true);
    //     global_config.set_asymmetric_cryptograph_type(handler_cipher);
    //     global_config.set_symmetric_cryptograph_type(method_enum);
    //     global_config.set_server_config(encrypt_content);
    //
    //     Ok((global_config, sec))
    // }

    // /**
    //  * while generating random_content in this method
    //  */
    // fn build_server_conf(ver: &str, pk_str: &Vec<u8>, method_enum: EncMethodEnum) -> ServerConfig {
    //     let ver_str = String::from(ver.clone());
    //     let version_data: Vec<&str> = ver_str.split("_").collect();
    //     let mut rng = StdRng::from_entropy();
    //     let mut random_content = vec![0u8; 32]; // 32 B
    //     rng.fill_bytes(&mut random_content);
    //
    //     let mut server_conf_prof = ServerConfig::new();
    //     server_conf_prof.set_pubkey(pk_str.to_owned());
    //     server_conf_prof.set_enc_method(method_enum.clone());
    //
    //     if version_data.len() == 3 {
    //         server_conf_prof.set_client_platform_type(version_data[0].to_owned());
    //         server_conf_prof.set_client_platform_version(version_data[1].to_owned());
    //         server_conf_prof.set_client_platform_category(version_data[2].to_owned());
    //     } else {
    //         error!("set_client_platform_version error: {}", ver_str);
    //     }
    //     server_conf_prof.set_random_content(random_content.to_owned());
    //     server_conf_prof
    // }
    //
    // async fn check_uid(uid: u64, src_stream: &mut AnyStream) -> UidStatusEnum {
    //     let mut global_config = GlobalConfig::default();
    //     global_config.set_client_unique_id(uid);
    //     let proto = Self::call_tcp_by_proto::<ClientUIDStatusRes>(&global_config, src_stream)
    //         .await
    //         .unwrap();
    //     proto.get_status()
    // }

    async fn call_tcp_by_proto<RESP: Message>(
        proto: &dyn Message,
        src_stream: &mut AnyStream,
    ) -> io::Result<RESP> {
        let pb = proto.write_to_bytes().unwrap();
        let mut buffer = BytesMut::new();
        buffer.put_u16(pb.len() as u16);
        buffer.put_slice(pb.as_slice());
        trace!(
            "call_tcp_by_proto send buffer, len:{}, hex:{:?}",
            pb.len(),
            hex::encode(&pb)
        );
        src_stream.write_all(&buffer).await?;

        let len = src_stream.read_u16().await?;
        let mut buffer = vec![0u8; len as usize];

        let res = match src_stream.read_exact(&mut buffer).await {
            Ok(_) => {
                trace!(
                    "call_tcp_by_proto response buffer，len:{}, hex:{:?}",
                    len,
                    hex::encode(&buffer)
                );
                let res = RESP::parse_from_bytes(buffer.as_slice()).expect(
                    format!(
                        "error protobuf parse_from_bytes error, buffer:{:?}",
                        hex::encode(buffer)
                    )
                    .as_str(),
                );
                res
            }
            Err(e) => {
                // 读取失败，处理错误
                panic!("Error: read from stream error {:?}", e);
            }
        };
        trace!("ask tcp request:{:?} \n response:{:? }", proto, &res);
        Ok(res)
    }
    async fn send_handler_global_conf(
        &self,
        global_conf: &GlobalConfig,
        src_stream: &mut AnyStream,
    ) -> io::Result<u64> {
        trace!("sever_conf_prof:{:?}", global_conf);
        let pb = global_conf.write_to_bytes().unwrap();
        let mut buffer = BytesMut::new();
        buffer.put_u16(pb.len() as u16);
        buffer.put_slice(pb.as_slice());
        trace!("write_server_conf:{:?}", buffer.to_vec());
        src_stream.write_all(&buffer).await?;
        let len = src_stream.read_u16().await?;

        let mut buffer = vec![0u8; len as usize];

        let uid = match src_stream.read_exact(&mut buffer).await {
            Ok(_) => {
                trace!("{:?}", buffer);
                let res = ClientUIDStatusRes::parse_from_bytes(buffer.as_slice()).expect(
                    format!(
                        "error ClientUIDStatusRes::parse_from_bytes buffer:{:?}",
                        hex::encode(buffer)
                    )
                    .as_str(),
                );
                res.client_unique_id
                    .expect(format!("error ClientUIDStatusRes has no uid  res:{:?}", res).as_str())
            }
            Err(e) => {
                // 读取失败，处理错误
                panic!("Error: {:?}", e);
            }
        };
        Ok(uid)
    }

    fn get_addr_from_config(&self) -> (String, u16) {
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
        (address, port)
    }
}
