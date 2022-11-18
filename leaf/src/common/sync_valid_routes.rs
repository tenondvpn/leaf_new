use std::thread;
use std::time::Duration;
use std::process;
use std::panic;
extern crate easy_http_request;
 
use easy_http_request::DefaultHttpRequest;
use std::sync::Mutex;
use lazy_static::lazy_static;
lazy_static! {
    static ref valid_routes: Mutex<String> = Mutex::new(String::from(""));
    static ref valid_tmp_id: Mutex<String> = Mutex::new(String::from(""));
    static ref started: Mutex<u32> = Mutex::new(0);
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
}

pub fn GetValidRoutes() -> String {
    valid_routes.lock().unwrap().clone()
}
