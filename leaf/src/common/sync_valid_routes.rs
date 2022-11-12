use std::thread;
use std::time::Duration;
use std::process;
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
            // let response = DefaultHttpRequest::get_from_url_str("https://jhsx123456789.xyz:14431/get_qr_code_balance_more?id=".to_string() + &valid_tmp_id.lock().unwrap().clone())
            //     .unwrap().send().unwrap();

            // let res = String::from_utf8(response.body).unwrap();
            // let tmp_vec: Vec<&str> = res.split(";").collect();
            // if (tmp_vec.len() >= 5 && res.starts_with("https")) {
                let mut v = valid_routes.lock().unwrap();
                v.push_str(&"34.207.135.30:36959,54.174.161.239:36238,3.92.142.157:36059,34.229.248.4:52549,54.81.130.146:48420,54.145.148.214:53844,35.153.169.230:56105,52.87.169.211:44370,23.22.56.189:63925,107.22.23.23:52928,3.82.15.16:38135,54.162.6.210:41127,54.86.63.250:38859,54.225.59.207:41309,34.207.56.191:49051,107.20.50.223:40685,54.81.166.176:45881,18.234.91.72:40710,34.207.102.127:63737,3.92.78.196:54975,54.162.83.116:47711,34.227.84.14:54124,54.81.22.5:51239,".to_string());

            //     let used_bw = tmp_vec[2].parse::<u32>().unwrap();
            //     let all_bw = tmp_vec[3].parse::<u32>().unwrap();
            //     if (used_bw != 0 && used_bw >= all_bw) {
            //         process::exit(1);
            //     }
            // }
              
            thread::sleep(Duration::from_millis(10000));
        }
    });
}

pub fn GetValidRoutes() -> String {
    valid_routes.lock().unwrap().clone()
}
