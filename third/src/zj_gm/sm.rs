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

pub fn gcm_encrypt_sm4() -> usize {
    // gcm_encrypt(plain_txt.as_ptr(), 10 ,
    //             out_txt.as_mut_ptr(),   Box::new(10).as_mut(),
    //             tag.as_mut_ptr(),   Box::new(16).as_mut(),
    //             key.as_ptr(), 16 ,
    //             iv.as_ptr(), 16 ,
    //             dec_txt.as_ptr(), 0,
    //             padding_t_NO_PADDING, symmetric_cryptograph_t_SM4);
    0
}

pub fn test_sm4(plain_txt: &str) -> String {
    let mut key = String::from("1234567890123456");
    let mut iv = String::from("1234567890123456");
    let mut tag = String::from("1234567890123456");

    // let key_len = key.len();
    // let key = CString::new(key).unwrap();
    // let mut key = key.into_raw() as *mut u8;

    let mut dec_txt = String::from("xxxxx ixxx");
    let mut out_txt = String::from("1lain text");

    let out_txt_len = out_txt.len();

    let tag_len = tag.len();

    let dec_txt_len = dec_txt.len();

    unsafe {
        println!("1111111111:");

        gcm_encrypt(
            plain_txt.as_ptr(),
            10,
            out_txt.as_mut_ptr(),
            Box::new(10).as_mut(),
            tag.as_mut_ptr(),
            Box::new(16).as_mut(),
            key.as_ptr(),
            16,
            iv.as_ptr(),
            16,
            dec_txt.as_ptr(),
            0,
            1,
            0,
        );

        gcm_decrypt(
            out_txt.as_ptr(),
            out_txt_len as size_t,
            dec_txt.as_mut_ptr(),
            Box::new(dec_txt_len as size_t).as_mut(),
            tag.as_mut_ptr(),
            tag_len as size_t,
            key.as_ptr(),
            16 as size_t,
            iv.as_ptr(),
            iv.len() as size_t,
            iv.as_ptr(),
            0,
            padding_t_NO_PADDING,
            symmetric_cryptograph_t_SM4,
        );
    }
    dec_txt.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm3() {
        println!("aaaaaaaaaastr:");
        let str = "123456";

        let buf = sm3_hash(str);
        println!("aaaaaaaaaastr:{}", str);
        println!("aaaaaaaaaaabuf:{:?}", buf);
    }

    #[test]
    fn a_test_sm4() {
        let mut plain_txt = String::from("plain text");

        let mut dec_str_buf = test_sm4(&plain_txt);
        println!("dec str: {}", dec_str_buf);
    }
}
