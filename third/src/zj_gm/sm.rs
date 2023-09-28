use std::ops::Deref;

use crate::zj_gm::bindings;
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

pub fn gcm_encrypt_sm4(
    plain_txt: &[u8],
    out_txt: &mut [u8],
    tag: &mut [u8],
    key: &[u8],
    iv: &[u8],
) -> usize {
    let mut result = 1;
    unsafe {
        result = gcm_encrypt(
            plain_txt.as_ptr(),
            plain_txt.len() as size_t,
            out_txt.as_mut_ptr(),
            Box::new(out_txt.len() as size_t).as_mut(),
            tag.as_mut_ptr(),
            Box::new(tag.len() as size_t).as_mut(),
            key.as_ptr(),
            key.len() as size_t,
            iv.as_ptr(),
            iv.len() as size_t,
            iv.as_ptr(),
            0,
            padding_t_NO_PADDING,
            symmetric_cryptograph_t_SM4,
        );
    }
    result as usize
}

pub fn gcm_decrypt_sm4(
    input: &[u8],
    dec_txt: &mut [u8],
    tag: &[u8],
    key: &[u8],
    iv: &[u8],
) -> usize {
    let mut result = 1;
    unsafe {
        result = gcm_decrypt(
            input.as_ptr(),
            input.len() as size_t,
            dec_txt.as_mut_ptr(),
            Box::new(dec_txt.len() as size_t).as_mut(),
            tag.as_ptr(),
            tag.len() as size_t,
            key.as_ptr(),
            key.len() as size_t,
            iv.as_ptr(),
            iv.len() as size_t,
            iv.as_ptr(),
            0,
            padding_t_NO_PADDING,
            symmetric_cryptograph_t_SM4,
        );
    }
    result as usize
}

pub fn generate_key_pair() {
    let mut pub_key = [0i8; 130];
    let mut private_key = [0i8; 64];
    let mut pub_key_len = Box::new(private_key.len() as size_t);
    let mut private_key_len = Box::new(pub_key.len() as size_t);
    unsafe {
        bindings::generate_key_pair(
            private_key.as_mut_ptr(),
            private_key_len.as_mut(),
            pub_key.as_mut_ptr(),
            pub_key_len.as_mut(),
            asymmetric_cryptograph_t_SM2,
        );
    }
    println!(
        "generated private key: {}-> {:?}",
        private_key_len, private_key
    );
    println!("generated pub_key key: {}-> {:?}", pub_key_len, pub_key);
}

pub fn asymmetric_encrypt_SM2(plain_txt: &[u8], pk: &[i8]) -> Vec<u8> {
    let mut out_txt_box = Box::new(vec![0u8; plain_txt.len() + 220]);
    let mut out_len = out_txt_box.len() as size_t;
    let out_txt_len_box = Box::new(&mut out_len);
    unsafe {
        println!("pk.len:{}", pk.len());
        match asymmetric_encrypt(
            plain_txt.as_ptr(),
            plain_txt.len() as size_t,
            pk.as_ptr() as *const i8,
            pk.len() as size_t,
            out_txt_box.as_mut_ptr(),
            *out_txt_len_box,
            asymmetric_cryptograph_t_SM2,
        ) {
            0 => {}
            i => {
                println!("Error: symmetric encryption failed :{}", i);
            }
        };
    }

    let split_index_usize: usize = out_txt_len_box.to_owned() as usize;
    out_txt_box.split_at_mut(split_index_usize).0.to_vec()
}

pub fn asymmetric_decrypt_SM2(input: &[u8], private_key: &[i8]) -> Vec<u8> {
    let mut out_txt_box = Box::new(vec![0u8; input.len() + 220]);

    let mut out_len = out_txt_box.len() as size_t;
    let out_txt_len = Box::new(&mut out_len);
    unsafe {
        println!("private_key.len:{}", private_key.len());
        match asymmetric_decrypt(
            input.as_ptr(),
            input.len() as size_t,
            private_key.as_ptr() as *const i8,
            private_key.len() as size_t,
            out_txt_box.as_mut_ptr(),
            *out_txt_len,
            asymmetric_cryptograph_t_SM2,
        ) {
            0 => {}
            i => {
                println!("Error: symmetric encryption failed :{}", i);
            }
        };
    }
    let split_index_usize: usize = out_txt_len.to_owned() as usize;
    out_txt_box.split_at_mut(split_index_usize).0.to_vec()
}

pub fn test_sm4(plain_txt: &str) -> String {
    let key = String::from("1234567890123456");
    let iv = String::from("1234567890123456");
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
    fn test_generate_key_pair() {
        generate_key_pair();
    }

    #[test]
    fn test_asymmetric_encrypt_SM2() {
        let enckey: Vec<i8> = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
            .as_bytes()
            .iter()
            .map(|&byte| byte as i8)
            .collect();
        let pk:Vec<i8>= "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
            .as_bytes().iter().map(|&byte| byte as i8).collect();

        let plaintext = "1234567890123456789012345678901234".to_string();
        let output = asymmetric_encrypt_SM2(plaintext.as_bytes(), pk.as_slice());

        println!("output: {:?}", output);

        let outPlaintext2 = asymmetric_decrypt_SM2(output.as_slice(), enckey.as_slice());

        assert_eq!(plaintext, String::from_utf8(outPlaintext2).unwrap())
    }

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
        let plain_txt = String::from("plain text");

        let dec_str_buf = test_sm4(&plain_txt);
        println!("dec str: {}", dec_str_buf);
    }
}
