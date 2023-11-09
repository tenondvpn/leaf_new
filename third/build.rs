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
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    println!("os is :{}", os);

    if arch.eq("x86_64") && os.eq("android") {
        let trarget_lib_str = libdir_path.join("x86_64-linux-android");
        println!(
            "cargo:rustc-link-search={}",
            trarget_lib_str.to_str().unwrap().to_owned()
        );
        println!(
            "cargo:rustc-env=LD_LIBRARY_PATH=$LD_LIBRARY_PATH:{}",
            trarget_lib_str.to_str().unwrap().to_owned()
        );
        // println!("cargo:rustc-link-lib=gmp");
        println!("cargo:rustc-link-lib=sm");
    }

    if arch.eq("aarch64") && os.eq("android") {
        let trarget_lib_str = libdir_path.join("aarch64-linux-android");
        println!(
            "cargo:rustc-link-search={}",
            trarget_lib_str.to_str().unwrap().to_owned()
        );
        println!(
            "cargo:rustc-env=LD_LIBRARY_PATH=$LD_LIBRARY_PATH:{}",
            trarget_lib_str.to_str().unwrap().to_owned()
        );
        // println!("cargo:rustc-link-lib=gmp");
        println!("cargo:rustc-link-lib=sm");
    }


    if arch.eq("x86_64") && os.eq("linux") {
        let trarget_lib_str = libdir_path.join("x86_64-linux");

        println!(
            "cargo:rustc-link-search={}",
            trarget_lib_str.to_str().unwrap()
        );
        //export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:`pwd
        println!(
            "cargo:rustc-env=LD_LIBRARY_PATH=$LD_LIBRARY_PATH:{}",
            trarget_lib_str.to_str().unwrap()
        );
        println!("cargo:rustc-link-lib=smcrypto");
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
