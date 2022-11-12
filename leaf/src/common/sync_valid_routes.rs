use std::thread;
use std::time::Duration;

extern crate easy_http_request;
 
use easy_http_request::DefaultHttpRequest;
use std::sync::Mutex;
use lazy_static::lazy_static;
lazy_static! {
    static ref valid_routes: Mutex<String> = Mutex::new(String::from(""));
}


pub fn StartThread() {
    thread::spawn(|| {
        while (true) {
            let response = DefaultHttpRequest::get_from_url_str("https://jhsx123456789.xyz:14431/get_qr_code_balance_more?id=b5be6f0090e4f5d40458258ed9adf843324c0327145c48b55091f33673d2d5a4")
                .unwrap().send().unwrap();

            let res = String::from_utf8(response.body).unwrap();
            let tmp_vec: Vec<&str> = res.split(";").collect();
            if (tmp_vec.len() >= 5) {
                let mut v = valid_routes.lock().unwrap();
                v.push_str(tmp_vec[4]);
            }
              
            thread::sleep(Duration::from_millis(10000));
        }
    });
}

pub fn GetValidRoutes() -> String {
    valid_routes.lock().unwrap().clone()
}
