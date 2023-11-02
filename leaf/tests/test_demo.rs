use std::fs::File;
use std::io::Write;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

#[test]
fn test_demo() {
    // setup_test_logger();
    let config_path = "config.conf".to_string();
    let opts = leaf::StartOptions {
        config: leaf::Config::File(config_path),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: leaf::RuntimeOption::MultiThreadAuto(1 * 1024 * 1024),
    };
    leaf::start(0, opts).unwrap();


}


pub fn setup_test_logger(){
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
fn test_rng() {
    let mut random_content = vec![0u8; 32]; // 32 B
    let mut rng = StdRng::from_entropy();

    rng.fill_bytes(&mut random_content);
    let mut file1 = File::create("rng.txt").unwrap();
    file1.write_all(random_content.as_slice()).unwrap();
}