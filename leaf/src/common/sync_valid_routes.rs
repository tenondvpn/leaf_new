use std::panic;
use std::process;
use std::thread;
use std::time::Duration;
//extern crate easy_http_request;
use std::collections::HashMap;

//use easy_http_request::DefaultHttpRequest;
use lazy_static::lazy_static;
use std::sync::Mutex;
lazy_static! {
    static ref valid_routes: Mutex<String> = Mutex::new(String::from(""));
    static ref valid_tmp_id: Mutex<String> = Mutex::new(String::from(""));
    static ref started: Mutex<u32> = Mutex::new(0);
    static ref connection_map: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

pub fn exchange_enc_password(json: String) {

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
    /*
    thread::spawn(|| {
        while (true) {
            let response = DefaultHttpRequest::get_from_url_str(
                "https://jhsx123456789.xyz:14431/get_qr_code_balance_more?id=".to_string() +
                &valid_tmp_id.lock().unwrap().clone())
                .unwrap().send();

            match response {
                Ok(response)=> {
                    let res = String::from_utf8(response.body).unwrap();
                    let tmp_vec: Vec<&str> = res.split(";").collect();
                    if (tmp_vec.len() >= 5 && res.starts_with("https")) {
                        let mut v = valid_routes.lock().unwrap();
                        v.push_str(tmp_vec[4]);

                        let used_bw = tmp_vec[2].parse::<u32>().unwrap();
                        let all_bw = tmp_vec[3].parse::<u32>().unwrap();
                        if (used_bw != 0 && used_bw >= all_bw) {
                            process::exit(1);
                        }
                    }
                },
                Err(e)=> {
                    println!("file not found \n{:?}",e);   // 处理错误
                }
            }

            thread::sleep(Duration::from_millis(10000));
        }
    });
    */
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
