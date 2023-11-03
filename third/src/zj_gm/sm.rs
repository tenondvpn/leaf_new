use std::error::Error;
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

pub fn generate_key_pair() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut pub_key = [0i8; 130];
    let mut private_key = [0i8; 64];
    let mut pub_key_len = Box::new(private_key.len() as size_t);
    let mut private_key_len = Box::new(pub_key.len() as size_t);
    unsafe {
        match bindings::generate_key_pair(
            private_key.as_mut_ptr(),
            private_key_len.as_mut(),
            pub_key.as_mut_ptr(),
            pub_key_len.as_mut(),
            asymmetric_cryptograph_t_SM2,
        ) {
            0 => {
                Ok((private_key.map(|x|  {x as u8}).to_vec(),
                    pub_key.map(|x| {x as u8}).to_vec()))
            }
            i => {
                let msg = format!("Error: generate_key_pair failed :{}", i);
                println!("Error: symmetric encryption failed :{}", i);
                Err(msg)
            }
        }
    }
}

pub fn asymmetric_encrypt_SM2(plain_txt: &[u8], pk: &[u8]) -> Result<Vec<u8>, String> {
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
            0 => {
                let split_index_usize: usize = out_txt_len_box.to_owned() as usize;
                Ok(out_txt_box.split_at_mut(split_index_usize).0.to_vec())
            }
            i => {
                let msg = format!("Error: symmetric encryption failed :{}", i);
                println!("Error: symmetric encryption failed :{}", i);
                Err(msg)
            }
        }
    }
}



pub fn asymmetric_decrypt_SM2(input: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
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
            0 => {
                let split_index_usize: usize = out_txt_len.to_owned() as usize;
                Ok(out_txt_box.split_at_mut(split_index_usize).0.to_vec())
            },
            i => {
                let msg = format!("Error: symmetric decrypt failed :{}", i);
                println!("Error: symmetric decrypt failed :{}", i);
                Err(msg)
            }
        }
    }
}
pub fn sig_SM2(plain_txt: &[u8], sec_key: &[u8], pk: &[u8]) -> Vec<u8> {
    let mut out_txt_box = Box::new(vec![0u8; plain_txt.len() + 220]);
    let mut out_len = out_txt_box.len() as size_t;
    let out_txt_len_box = Box::new(&mut out_len);
    let id = "123".to_string();
    unsafe {
        println!("sec_key.len:{}", sec_key.len());
        match sign(
            plain_txt.as_ptr(),
            plain_txt.len() as size_t,
            id.as_ptr() as *const i8,
            id.as_bytes().len() as size_t,
            Box::new(pk.to_vec()).as_ptr() as *const i8,
            pk.len() as size_t,
            sec_key.as_ptr() as *const i8,
            sec_key.len() as size_t,
            out_txt_box.as_mut_ptr(),
            *out_txt_len_box,
            asymmetric_cryptograph_t_SM2,
        ) {
            0 => {}
            i => {
                println!("Error: symmetric sig_SM2 failed :{}", i);
            }
        };
    }

    let split_index_usize: usize = out_txt_len_box.to_owned() as usize;
    out_txt_box.split_at_mut(split_index_usize).0.to_vec()
}


pub fn verify_SM2(plain_txt: &[u8], signature:&[u8], pk: &[u8]) -> i32 {
    let id = "123".to_string();

    unsafe {
        println!("pk.len:{}", pk.len());
        verify(
            plain_txt.as_ptr(),
            plain_txt.len() as size_t,
            id.as_ptr() as *const i8,
            id.as_bytes().len() as size_t,
            signature.as_ptr(),
            signature.len() as size_t,
            Box::new(pk.to_vec()).as_ptr() as *const i8,
            pk.len() as size_t,
            asymmetric_cryptograph_t_SM2,
        )
    }

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
    use hex::encode;
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let (enc,pk) = generate_key_pair().unwrap();

    }

    #[test]
    fn test_sm2_signed() {
        let (enckey, pk) = use_const_pk();
        let signature = sig_SM2(plain_from_server().as_bytes(), enckey.as_slice(), pk.as_slice());
        println!("signature: {}", hex::encode(&signature));
        let result = verify_SM2(plain_from_server().as_bytes(), signature.as_slice(), pk.as_slice());
        assert_eq!(result, 0)
    }

    #[test]
    fn test_asymmetric_encrypt_SM2() {
        let (enckey, pk) = use_const_pk();
        println!("pk_hex :{}", hex::encode(&pk));
        println!("pk: {:?}", &pk);

        let plaintext = "1234567890123456789012345678901234".to_string();
        let output = asymmetric_encrypt_SM2(plaintext.as_bytes(), pk.as_slice()).unwrap();

        println!("output: {:?}", output);

        let outPlaintext2 = asymmetric_decrypt_SM2(output.as_slice(), enckey.as_slice()).unwrap();

        assert_eq!(plaintext, String::from_utf8(outPlaintext2).unwrap())
    }



    #[test]
    fn tetst_verify_sm2() {

        let plain = "0880a098dc849ad81b121811ff00fe000400ff00ff000c00d0000000800070ff300000";
        let server_pk = "30343039463944463331314535343231413135304444374431363145344243354336373231373946414431383333464330373642423038464633353646333530323043434541343930434532363737354135324443364541373138434331414136303041454430354642463335453038344136363332463630373244413941443133".as_bytes();
        let signature = "304502207620b4cdb49b4fe5b2e149717ca3a0e1095a2a99a7de7072d134e98953dbf9f6022100b6c2c124eb391ca874e4d478fcd433f1742d44109c6685797a6ed21a73009d28";

        let plain = hex::decode(&plain).unwrap();
        let signature = hex::decode(&signature).unwrap();
        let server_pk = hex::decode(&server_pk).unwrap();
        let result = verify_SM2(plain.as_slice(), signature.as_slice(), server_pk.as_slice());
        assert_eq!(result, 0)
    }

    fn plain_from_server() -> String {
        let hex = "0880a098dc849ad81b121811ff00fe000400ff00ff000c00d0000000800070ff300000".to_string();
        let hex = hex.replace("\\n", "");
        hex
    }
    fn encode_from_server() -> Vec<u8> {
        let hex = "30818c022052caaed3b7cdf22eb9690e9969e32c50bd7301357199877
8cb5aa95ab29cf3ff022100c44f66756ab3f62f7a449cc699f685deb04a0470dc094d2a0e6c55771e31ea900420e0626535e0e8d0cdaf27a278b42a1ec9a514c6b7aa715275b41ce61b9ea78eec04237942283e20a6af056ce682360691b3bf626e661ae19ab9a7ca4330ccee5
2c2ebe7cab7".to_string();
        let hex = hex.replace("\n", "");
        hex::decode(&hex).unwrap()
    }

    fn signature_from_server() -> Vec<u8> {
        let hex = "3045022100d731b16c952fa97ba314914c15fb8901daf2c59e26952d59f65c5930f79ad6e302205b4df1d7507ab437bcfdc74a6c9c868ea2d96a490ec33449aaa056436251e0bd".to_string();
        hex::decode(&hex).unwrap()
    }
    fn encode_form_client() -> String {
        "".to_string()
    }

    fn use_test_client_key() -> (Vec<u8>, Vec<u8>) {
        let enckey = hex::decode("62656563356638313064303433333839653330663664653137363365636632313132383037613230663939333335383230656233626431306137633563333531".as_bytes()).unwrap().to_owned();
        let pk = hex::decode("30343832346433626436316233623165616230353038353661336439353332393932326562653162383036323834316463303534336163336532396533366333356338376661653030343232386661643061663063663261643037396237303432366466636566323264363734366364333862303431666331653431333137303830".as_bytes()).unwrap().to_owned();
        (enckey, pk)
    }

    fn use_const_pk() -> (Vec<u8>, Vec<u8>) {
        // let enckey = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
        //     .as_bytes().to_vec();
        // let pk = "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
        //     .as_bytes().to_vec();

        let enckey = hex::decode("33393435323038463742323134344231334633364533384143364433394639353838393339333639323836304235314134324642383145463444463743354238".as_bytes()).unwrap().to_owned();
        let pk = hex::decode("30343039463944463331314535343231413135304444374431363145344243354336373231373946414431383333464330373642423038464633353646333530323043434541343930434532363737354135324443364541373138434331414136303041454430354642463335453038344136363332463630373244413941443133".as_bytes()).unwrap().to_owned();
        (enckey, pk)
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

    #[test]
    fn test_gen_sm2_key() {
        let (enc, pk) = generate_key_pair().unwrap();
        println!("dec str: {}", hex::encode(enc));
        println!("pk str: {}",hex::encode(pk));
    }
}
