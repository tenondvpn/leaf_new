use crate::zj_gm::bindings::*;
use crate::zj_gm::bindings::{size_t, sm3_ctx_t};

pub fn sm3_hash(str: &str) -> [u8; 32] {
    let mut sm3_ctx = sm3_ctx_t {
        digest: [0u32; 8],
        nblocks: 0u32,
        block: [0u8; 64usize],
        num: 0u32,
    };
    let mut buf = [0u8; 32];
    unsafe {
        SM3Init(&mut sm3_ctx);
        SM3Update(&mut sm3_ctx, str.as_ptr(), str.len() as size_t);
        SM3Final(&mut sm3_ctx, buf.as_mut_ptr());
    }
    buf
}

#[test]
fn test_sm3() {
    println!("aaaaaaaaaastr:");
    let str = "123456";

    let buf = sm3_hash(str);
    println!("aaaaaaaaaastr:{}", str);
    println!("aaaaaaaaaaabuf:{:?}", buf);
}
