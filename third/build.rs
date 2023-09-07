extern crate bindgen;

use std::env;
use std::path::PathBuf;

use bindgen::CargoCallbacks;

fn main() {
    build_zj_sm();
}

fn build_zj_sm() {
    let libdir_path = PathBuf::from("src/zj_gm")
        .canonicalize()
        .expect("cannot canonicalize path");
    let headers_path = libdir_path.join("api.h");
    let headers_path_str = headers_path.to_str().expect("Path is not a valid string");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if arch.eq("x86_64") {
        println!(
            "cargo:rustc-link-search={}",
            libdir_path.join("x86_64-linux-android").to_str().unwrap()
        );
        println!("cargo:rustc-link-lib=sm");
        println!("cargo:rustc-link-lib=gmp");
    }

    let bindings = bindgen::Builder::default()
        .header(headers_path_str)
        .parse_callbacks(Box::new(CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = libdir_path.join("bindings.rs");
    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
