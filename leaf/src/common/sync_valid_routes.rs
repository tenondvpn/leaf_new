//extern crate easy_http_request;
use std::collections::HashMap;
use std::error::Error;
use std::ops::Deref;
use std::sync::{Mutex, RwLock};
use std::thread;
use std::time::Duration;

use futures_util::TryFutureExt;
//use easy_http_request::DefaultHttpRequest;
use lazy_static::lazy_static;
use log::{debug, error, trace};
use protobuf::Message;
use rand::{Rng, RngCore, SeedableRng, thread_rng};
use rand::rngs::StdRng;
use rand::seq::IteratorRandom;
use tokio::time::timeout;

use third::zj_gm::sm::{asymmetric_decrypt_SM2, asymmetric_encrypt_SM2, generate_key_pair, sig_SM2, verify_SM2};

use crate::common::error_queue::push_error;
use crate::proto::client_config::{ClientNode, CryptoMethodInfo, ProxyNode};
use crate::proto::client_config::ErrorType::{change_password_error, rust_error};
use crate::proto::server_config::{EncMethodEnum, GlobalConfig, PasswordResponse, PasswordResponseData, ResponseStatusEnum, ServerConfig};

lazy_static! {
    static ref valid_routes: Mutex<String> = Mutex::new(String::from(""));
    static ref valid_tmp_id: Mutex<String> = Mutex::new(String::from(""));
    static ref started: Mutex<u32> = Mutex::new(0);
    static ref connection_map: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref password_map: RwLock<HashMap<String, ProxyNode>> = RwLock::new(HashMap::new());
    static ref password_not_empty_notify : tokio::sync::Notify = tokio::sync::Notify::new();
}

 pub fn exchange_enc_password(json: String) {
     trace!("password :{:?}", &json);
    let mut client_node: ClientNode =  if let Ok(t) =  serde_json::from_str(&json)
        .map_err(|e| push_error(change_password_error, "解析配置文件失败".to_owned())) {
        t
    } else {
        return;
    };
    let loginfo = client_node.get_user_login_information().to_owned();
     clean_cache();
    tokio::spawn(async move {
        for proxy_node in client_node.mut_node_list() {
            let login_info_c = loginfo.clone();
            let symmetric_crypto_method_type = proxy_node.get_symmetric_crypto_info().get_enc_method_type();
            // debug!{"symmetric_crypto_method_type:{:?}", symmetric_crypto_method_type};
            if symmetric_crypto_method_type.eq(&EncMethodEnum::NO_ENC) {
                debug!("not need swap password");

            } else {
                if let Err(e) = exchange_password_by_http(proxy_node, login_info_c).await {
                    error!("failed to exchange password :{:?}", e);
                    push_error(change_password_error, "交换密钥失败".to_owned())
                }
                debug!("need swap password");

            }
            save_enc_2_cache(proxy_node);
        }
    });

}

pub async fn wait_for_password_notification() {
    timeout(Duration::from_secs(10), async move{
        password_not_empty_notify.notified().await;
        trace!("password_notification_ed");
    } )
        .await
        .map_err(|error| {
            error!("error: {}", error);
            push_error(change_password_error, "".to_string());
        }).unwrap_or(());
}

pub async fn exchange_password_by_http(proxy_node: &mut ProxyNode, log_info: String) -> Result<(), Box<dyn Error>>{
    gen_client_sm2_pair(proxy_node).map_err(|err| push_error(change_password_error, "生成SM2 公私钥对失败".to_string())).unwrap_or(());
    // trace!("exchange_password_by_http 0: gen_client_sm2_pair succeeded");

    let (mut global_config, client_random) = build_global_conf(proxy_node, log_info)
        .map_err(|err|
            {push_error(change_password_error, "构建交换密钥报文失败".to_string()); err}
        )?;
    // trace!("exchange_password_by_http 1: build_global_conf succeeded");
    // trace!("exchange_password_by_http global_config:\n {}", &serde_json::to_string(&global_config)?);

    let client = reqwest::Client::new();
    // todo : http 端口
    let url = format!("http://{}:{}/exchange", &proxy_node.get_server_address(), 19802);


    // let mock_server_hex = "3082013602200ba27589b1851c1921e960510217b5f96841ca9acfe31c89f6110e9063465c2f022100877547fb71ad6890819ca43a6dce6190c95ba2e91262644a47dd7d112a8d226f04206668dabd009021becbe5518750e49c9964454eaa89d3f3f6ca822160b15f690e0481cc0ae0a03e57902125c3d603e297b07d7034a7485a6e0971f33c390e69948dd75cb2f4154d5829e26c7eee955d8bda7b4c9f83599cec323c523c7cae11fc447ad21a886befb08da03f93d79d93c7e787c9ed5d9bf58745db3d12ed8ec1568beeb53879c36a7f6454627ca7a076146a18c2eb8395e9b15b5e57dd61ddf78eceaec9b9ef16a57cf864ae390adb0825ea3dd9ee32e6a247af67db336552ab294a9b1cefe74b7a40995c09fc2b9a9c9b9baeff1b348132e74245e9034799d5db549443b087109411238dc6b24e0de5";
    // global_config.set_server_config(mock_server_hex.to_owned());
    // trace!("mock global_config :{:?}", &global_config);

    let res = client.post(url)
        .json(&global_config)
        .send()
        .await.map_err(|error| {
        error!("serde_json::from_str(PasswordResponse) error,{}", error);
        push_error(change_password_error, "解析服务端返回结果失败".to_string());
        error
    })?;
    // trace!("exchange_password_by_http 2: send proxy server succeeded");
    let res =res.text().await?;
    // trace!("exchange_password_by_http2: response:{}", &res);
    let res:PasswordResponse = serde_json::from_str(res.as_str()).map_err(|error| {
        error!("serde_json::from_str(PasswordResponse) error,{}", error);
        push_error(change_password_error, "".to_string());
        error
    })?;

    // trace!("exchange_password_by_http 3: map json succeeded");

    if res.get_status() == ResponseStatusEnum::PASSWORD_SUCCESS {

        let data = hex::decode(res.get_data()).map_err(|e| { push_error(rust_error, e.to_string()); e})?;
        let signature = hex::decode(res.get_check_value())?;
        let response: PasswordResponseData = decode_response(data,
                                                             signature,
                                                             proxy_node.get_asymmetric_crypto_info())?;
        // trace!("exchange_password_by_http 4: decode_response succeeded  \n {:?}", &response);
        let sm4_sec = gen_password(hex::decode(client_random)?,
                                   hex::decode(response.get_server_random())?)?;
        // trace!("exchange_password_by_http 5: gen_password succeeded,uid:{:?}, sec: {:?}",
        //     &response.get_client_unique_id(),
        //     hex::encode(&sm4_sec));

        proxy_node.mut_symmetric_crypto_info().set_client_unique_id(response.get_client_unique_id());
        proxy_node.mut_symmetric_crypto_info().set_sec_key(sm4_sec);
    } else {
        push_error(change_password_error, "服务器返回交换密要信息失败".to_string());
    };
    Ok(())
}

fn decode_response<T: Message>(encode_data: Vec<u8>, signature: Vec<u8>, asymmetric_info: &CryptoMethodInfo) -> Result<T, String> {
    let client_sec = asymmetric_info.get_client_sec_key();


    let plain_bin =  if let Ok(plain_bin) = asymmetric_decrypt_SM2(encode_data.as_slice(), client_sec) {
        plain_bin
    } else {
        push_error(change_password_error, "sm2解密失败".to_string());
        return Err(format!("sm2解密失败"));
    };



    let pk =String::from(asymmetric_info.get_server_pubkey());
    let server_pk = if let Ok(t) = hex::decode(pk) {
        t
    } else {
        return Err(format!("decode_response decode error"));
    };

    trace!("asymmetric_decrypt_SM2 succeeded");
    match verify_SM2(plain_bin.as_slice(), signature.as_slice(), server_pk.as_slice()) {
        0 => {}
        i => {
            let msg =format!("error verify_SM2 failed: {} \n planin_bin:{:?} \n signature:{:?} \n server_pk:{:?} "
                             , i, hex::encode(&plain_bin), hex::encode(&signature), hex::encode(&server_pk));
            trace!("{}", &msg);
            push_error(change_password_error, "sm2验证失败".to_string());
            return Err(format!("sm2验证失败"));
        }
    } ;
    trace!("exchange_password_by_http  verify_SM2 succeeded");

    if let Ok(t) = T::parse_from_bytes(plain_bin.as_slice()) {
        Ok(t)
    } else {
        push_error(change_password_error, "".to_string());
        return Err(format!("change_password_error ： parse_from_bytes error"))
    }

}

fn gen_client_sm2_pair(proxy_node: &mut ProxyNode) -> Result<(), Box<dyn Error>>  {
    let (enc,pk) = generate_key_pair()?;
    #[cfg(test)]
    {
        let (enc,pk) = use_test_client_key();
    }
    proxy_node.mut_asymmetric_crypto_info().set_client_pk(pk);
    proxy_node.mut_asymmetric_crypto_info().set_client_sec_key(enc);
    Ok(())
}

fn gen_password(p0: Vec<u8>, p1: Vec<u8>) -> Result<Vec<u8>, String> {
    trace!("p0.len {:?}, {:?} ", p0.len(), hex::encode(&p0));
    trace!("p1.len {:?}, {:?}", p1.len(), hex::encode(&p1));
    if p0.len() != p1.len() {
        push_error(change_password_error, "合成密钥失败".to_string());
        return Err("合成密钥失败".to_string()) ;
    }

    let mut p:Vec<u8> = vec![0; p0.len()];
    for (i, p0v) in p0.iter().enumerate() {
        p[i] = p0v ^ p1[i];
    }
    Ok(p)
}


fn save_enc_2_cache(p0: &ProxyNode) {
    password_not_empty_notify.notify_one();
    trace!("密钥交换完成：{:?}", &p0);
    set_password_map_set(p0);
}

fn build_global_conf(proxy_node: &ProxyNode, log_info: String) -> Result<(GlobalConfig, String), Box<dyn Error>> {
    let mut server_config = build_server_conf(proxy_node, log_info)?;
    let (encrypted_content, signature) = sm2_encode(proxy_node, &mut server_config)?;

    let mut global_config = GlobalConfig::new();
    global_config.set_current_message_encrypted(true);
    global_config.set_asymmetric_cryptograph_type(proxy_node.get_asymmetric_crypto_info().get_enc_method_type());
    global_config.set_symmetric_cryptograph_type(proxy_node.get_symmetric_crypto_info().get_enc_method_type());
    global_config.set_server_config(encrypted_content);
    global_config.set_check_value(signature);
    global_config.set_client_unique_id(0);

    Ok((global_config, server_config.get_random_content().to_owned()))
}

fn sm2_encode(proxy_node: &ProxyNode, server_config: &mut ServerConfig) -> Result<(String, String), Box<dyn Error>> {
    // trace!("Before  SM2 server_config: {:?}", &server_config);
    let server_conf_bin = server_config.write_to_bytes()?;

    let asymmetric_info = proxy_node.get_asymmetric_crypto_info();
    let pk = hex::decode(&asymmetric_info.get_server_pubkey())?;
    // trace!("pk==pk0:{:?}, pk:{:?}",&pk.eq(&use_test_server_key().1.as_slice()), &pk);
    // todo: in the future we need use method_enum to handle encrypt method
    let encrypt_content_1 = asymmetric_encrypt_SM2(&server_conf_bin.as_slice(), &pk.as_slice())?;
    let encrypted_content = hex::encode(&encrypt_content_1);


    let signature = sig_SM2(&server_conf_bin.as_slice(), &asymmetric_info.get_client_sec_key(), &asymmetric_info.get_client_pk());
    let signature = hex::encode(&signature);
    // trace!("After  SM2 server_config: {:?} \n signature:{:?} \n client_enc_key:{} \n client_pk{}", &encrypted_content,
    //     &signature,
    //     hex::encode(&asymmetric_info.get_client_sec_key()),
    //     hex::encode(&asymmetric_info.get_client_pk()));
    Ok((encrypted_content,signature))
}

/**
 * with generating random_content in this method
 */
fn build_server_conf(proxy_node: &ProxyNode, log_info: String) -> Result<ServerConfig, Box<dyn Error>> {
    let mut rng = StdRng::from_entropy();
    let mut random_content = vec![0u8; 48]; // 32 B
    rng.fill_bytes((&mut random_content).as_mut());



    let asymmetric_info = proxy_node.get_asymmetric_crypto_info();

    let mut server_conf_prof = ServerConfig::new();
    server_conf_prof.set_user_login_information(log_info);
    server_conf_prof.set_client_pk(hex::encode(asymmetric_info.get_client_pk()));
    server_conf_prof.set_pubkey(String::from(asymmetric_info.get_server_pubkey()));
    server_conf_prof.set_enc_method(asymmetric_info.get_enc_method_type().clone());
    server_conf_prof.set_client_platform_type(String::from(proxy_node.get_client_platform_type()));
    server_conf_prof.set_client_platform_version(String::from(proxy_node.get_client_platform_version()));
    server_conf_prof.set_client_platform_category(String::from(proxy_node.get_client_platform_category()));
    server_conf_prof.set_random_content(hex::encode(&random_content));
    Ok(server_conf_prof)
}



pub fn StartThread(id: String) {
    let mut v = started.lock().unwrap();
    if (*v > 0) {
        return;
    }

    *v = 1;
    {
        let mut tmp_v = valid_tmp_id.lock().unwrap();
        tmp_v.push_str(&id.clone());
    }
}

pub fn GetValidRoutes() -> String {
    let res = valid_routes.lock().unwrap().clone();
    valid_routes.lock().unwrap().clear();
    res
}

pub fn SetValidRoutes(data: String) {
    let mut v = valid_routes.lock().unwrap();
    v.push_str(&data);
    v.push_str(",");
}

pub fn SetResponseHash(svr_add: String, val: String) {
    let mut v = connection_map.lock().unwrap();
    v.insert(svr_add, val);
}

pub fn GetResponseHash(svr_add: String) -> String {
    let mut v = connection_map.lock().unwrap();
    let tmp = "".to_string();
    let val = v.get(&svr_add).unwrap_or(&tmp);
    val.to_string()
}

pub fn set_password_map_set(proxy_node: &ProxyNode) {
    let key = format!("{}:{}", proxy_node.get_server_address(), proxy_node.get_server_port());
    if let Ok (mut map) = password_map.write() {
        map.insert(key, proxy_node.to_owned());
    } else {
        error!("failed to write password")
    };
}

pub fn clean_cache() {
    trace!("clean_cache");
    if let  Ok( mut map) =  password_map.write() {
        map.clear();
    } else {
        error!("failed to clear password");
    }
}

pub fn password_map_get(server_address:&str, server_port:u32) -> Option<ProxyNode> {
    let key = format!("{}:{}", &server_address, server_port);
    let mut map = read_password_map();
    map.get(key.as_str()).cloned()
}

pub fn read_password_map<'a>() -> HashMap<String, ProxyNode> {
    let map = match password_map.read() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            error!("read password map failed");
            HashMap::new()
        }
    };
    return map;
}

fn is_password_map_empty() -> bool {
    let map = read_password_map();
    let bool = map.is_empty();
    bool
}


pub fn get_random_password_from_map() -> Option<ProxyNode> {
    let map = match password_map.read() {
        Ok(map) => map,
        Err(e) => {
            push_error(change_password_error, "".to_string());
            error!("password_map.read() failed: {}", e);
            return None;
        }
    };
    let mut rng = thread_rng();
    let random_index = rng.gen_range(0..map.len());

    if let Some(node) = map.values().nth(random_index) {
        Some(node.clone())
    } else {
        error!("map is empty: {:?}", map);
        None
    }
}


fn use_test_server_key() -> (Vec<u8>, Vec<u8>) {
    // let enckey = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
    //     .as_bytes().to_vec();
    // let pk = "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
    //     .as_bytes().to_vec();

    let enckey = hex::decode("33393435323038463742323134344231334633364533384143364433394639353838393339333639323836304235314134324642383145463444463743354238".as_bytes()).unwrap().to_owned();
    let pk = hex::decode("30343039463944463331314535343231413135304444374431363145344243354336373231373946414431383333464330373642423038464633353646333530323043434541343930434532363737354135324443364541373138434331414136303041454430354642463335453038344136363332463630373244413941443133".as_bytes()).unwrap().to_owned();
    (enckey, pk)
}

fn use_test_client_key() -> (Vec<u8>, Vec<u8>) {


    let enckey = hex::decode("62656563356638313064303433333839653330663664653137363365636632313132383037613230663939333335383230656233626431306137633563333531".as_bytes()).unwrap().to_owned();
    let pk = hex::decode("30343832346433626436316233623165616230353038353661336439353332393932326562653162383036323834316463303534336163336532396533366333356338376661653030343232386661643061663063663261643037396237303432366466636566323264363734366364333862303431666331653431333137303830".as_bytes()).unwrap().to_owned();
    (enckey, pk)
}


#[cfg(test)]
mod tests {
    use bytes::{BufMut, BytesMut};
    use log::debug;
    use protobuf::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::common::sync_valid_routes::exchange_password_by_http;
    use crate::exchange_password;
    use crate::proto::client_config::{ClientNode, CryptoMethodInfo, ProxyNode};
    use crate::proto::server_config::{EncMethodEnum, GlobalConfig, PasswordResponse, ResponseStatusEnum};
    use crate::proto::server_config::EncMethodEnum::SM4_GCM;

    #[tokio::test]
    pub async fn test_build_global_config() {
        setup_logger();
        let mut node1 = ProxyNode::new();
        node1.set_server_address("10.101.20.31".to_string());
        node1.set_server_port(19802);
        node1.set_client_platform_version("1".to_string());
        node1.set_client_platform_type("2".to_string());
        node1.set_client_platform_version("1".to_string());
        let mut info = CryptoMethodInfo::new();
        info.set_enc_method_type(EncMethodEnum::SM2);
        info.set_sec_key(vec![1,2,3,4,5,6,7,8,9,10]);
        let mut pk2 = "30343039463944463331314535343231413135304444374431363145344243354336373231373946414431383333464330373642423038464633353646333530323043434541343930434532363737354135324443364541373138434331414136303041454430354642463335453038344136363332463630373244413941443133";

        info.set_server_pubkey(pk2.to_owned());
        node1.set_asymmetric_crypto_info(info);

        println!("Building global config1");
        exchange_password_by_http(&mut node1, "21231243".to_string()).await;
    }
    #[test]
    pub  fn test_password_reponse() {
        let mut response = PasswordResponse::new();
        response.set_status(ResponseStatusEnum::PASSWORD_SUCCESS);
        println!("{:?}", serde_json::to_string(&response).unwrap());
    }
    #[test]
    pub fn test_log() {
        setup_logger();
        let mut node1 = ProxyNode::new();
        node1.set_server_address("10.101.20.31".to_string());
        node1.set_server_port(19802);
        let url = format!("http://{}:{}/exchange", &node1.get_server_address(), node1.get_server_port());

        debug!("{url}");
    }


    #[test]
    pub fn test_node_list() {
        let json = get_node_list_test_json();

        println!("{}", json);
    }

    fn get_node_list_test_json() -> String {
        let mut node1 = ProxyNode::new();
        node1.set_server_address("10.101.20.31".to_string());
        node1.set_server_port(19802);

        let mut info = CryptoMethodInfo::new();
        info.set_enc_method_type(EncMethodEnum::SM2);
        let mut pk2 = "30343039463944463331314535343231413135304444374431363145344243354336373231373946414431383333464330373642423038464633353646333530323043434541343930434532363737354135324443364541373138434331414136303041454430354642463335453038344136363332463630373244413941443133";
        info.set_server_pubkey(pk2.to_owned());

        node1.set_asymmetric_crypto_info(info);

        let mut info = CryptoMethodInfo::new();
        info.set_enc_method_type(EncMethodEnum::SM4_GCM);

        node1.set_symmetric_crypto_info(info);


        let mut vec = Vec::new();
        vec.push(node1);

        let mut client_node = ClientNode::default();
        client_node.set_node_list(vec.into());
        let loginfo = "{\"username\":\"username\",\"login_timestamp\":\"1698739833\",\"rand_str\":\"123456\",\"app_version\":\"v1.0\",\"access_token\":\"2a17e53283d1c1aca454240895200331ca7f0e5294447d20f0336e2f8dcc31ce\",\"signature\":\"3046022100ab35122c562c338c5a519b2eac9fcd90fbd9f198a238f6501b824442cb5367820221008d2c26a84fcf10ca33cdf2ee303d2841f6c4496771ba084c528c022d490679ae\"}";
        client_node.set_user_login_information(loginfo.to_string());

        let json = serde_json::to_string_pretty(&client_node).unwrap();
        json
    }

    fn setup_logger(){
        fern::Dispatch::new()
            .format(|out, message, record| {
                out.finish(format_args!(
                    "{}[{}][{}] {}",
                    chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                    record.target(),
                    record.level(),
                    message
                ))
            })
            .level(log::LevelFilter::Trace)
            .chain(std::io::stdout())
            .chain(fern::log_file("output.log").unwrap())
            .apply().unwrap();
    }

    #[test]
    fn test_exchange_enc_password() {
        setup_logger();
        let string = get_node_list_test_json();
        exchange_password(string.clone());
       // rt.block_on(wait_for_password_notification());
    }


    #[test]
    fn test_passwod_response() {
        let mut point = PasswordResponse::default();
        point.set_status(ResponseStatusEnum::PASSWORD_ERROR);
        point.set_error_message("1234".to_string());
        // point.set_check_value();

        // Convert the Point to a JSON string.
        let serialized = serde_json::to_string(&point).unwrap();

        println!("serialized = {}", serialized);

        // Convert the JSON string back to a Point.
        let deserialized: PasswordResponse = serde_json::from_str(r#"{"status": "PASSWORD_ERROR", "error_message": "verify failed", "check_value": ""}"#).unwrap();

        // Prints deserialized = Point { x: 1, y: 2 }
        println!("deserialized = {:?}", deserialized);
    }

    #[tokio::test]
   async fn test_tcp()  {

        let handle1 =tokio::spawn(async { tcp_server_demo().await; });
        let handle = tokio::spawn(async { tcp_send_demo().await; });
        handle1.await.unwrap();

        handle.await.unwrap();




    }

    async fn tcp_server_demo() {
        let listener = TcpListener::bind("127.0.0.1:8882").await.unwrap();
        match listener.accept().await {
            Ok((mut socket, addr)) => {
                println!("Connection received! {:?} is sending data.", addr);
                let mut buffer = BytesMut::with_capacity(100);
                socket.read_buf(&mut buffer).await.unwrap();
                println!("received data: {:?}",hex::encode( &buffer[..]));
                socket.write_all("1234".as_bytes()).await.unwrap();
            },
            Err(e) => println!("couldn't get client: {:?}", e),
        }
    }



    async fn tcp_send_demo() {
        let server_address = "127.0.0.1:8882"; // 修改为你要测试的服务器地址和端口
        let mut stream = TcpStream::connect(server_address).await.unwrap();

        let mut global_config = GlobalConfig::default();
        global_config.set_current_message_encrypted(true);
        global_config.set_symmetric_cryptograph_type(SM4_GCM);

        global_config.set_client_unique_id(15720307825053696);
        let password =
            hex::decode("3ae2318f26a20a142d231b618a139ea17ae38b558071b9a4b16fab14c53973f19884e0ba3b495747fdccd32a88c6720e").unwrap();

        let pb = &global_config.write_to_bytes().unwrap();
        let mut buffer = BytesMut::new();
        buffer.put_u16(pb.len() as u16);
        buffer.put_slice(pb.as_slice());
        println!("send fist global_config :{:?}, pb.len:{:?}, pb.hex:{:?}", &global_config, pb.len(), hex::encode(pb.as_slice()));
        match stream.write_all(&buffer).await
        {
            Ok(a) => { println!("send successfully") }
            Err(e) => { println!("send error ：{:?}", e); }
        }; // 注意这里是明文


        let mut buffer = [0; 1024];
        let mut response = String::new();

        loop {
            match stream.read(&mut buffer).await {
                Ok(bytes_received) => {
                    if bytes_received == 0 {
                        break;
                    }
                    let chunk = hex::encode(&buffer[..bytes_received]);
                    println!("recive {:?}", chunk);
                }
                Err(e) => { println!("error: {:?}", e); }
            }
        }
    }
}
