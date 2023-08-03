
#[test]
fn test_demo() {
    let config_path = "config.conf".to_string();
    let opts = leaf::StartOptions {
        config: leaf::Config::File(config_path),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: leaf::RuntimeOption::MultiThreadAuto(1 * 1024 * 1024),
    };
    leaf::start(0, opts).unwrap();
}