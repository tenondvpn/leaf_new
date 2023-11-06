use std::error::Error;
use std::ffi::CString;
use log::{error, trace};

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
    let key = Box::new(key.to_vec());
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
                error!("Error: symmetric encryption failed :{}", i);
                Err(msg)
            }
        }
    }
}

pub fn asymmetric_encrypt_SM2(plain_txt: &[u8], pk: &[u8]) -> Result<Vec<u8>, String> {
    let mut out_txt_box = Box::new(vec![0u8; plain_txt.len() + 220]);
    let mut out_len = out_txt_box.len() as size_t;
    let out_txt_len_box = Box::new(&mut out_len);
    let pk_len = pk.len();
    let pk = CString::new(pk).unwrap();
    unsafe {
        trace!("pk.len:{}", pk_len);
        match asymmetric_encrypt(
            plain_txt.as_ptr(),
            plain_txt.len() as size_t,
            pk.as_ptr(),
            pk_len as size_t,
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
                error!("Error:  asymmetric_encrypt_SM2 failed :{}, \n pk:{}, \n input : {} ", i, hex::encode(&pk.as_bytes()), hex::encode(&plain_txt));
                Err(msg)
            }
        }
    }
}



pub fn asymmetric_decrypt_SM2(input: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
    let mut out_txt_box = Box::new(vec![0u8; input.len() + 220]);

    let private_len = private_key.len();
    let private_key = CString::new(private_key).unwrap();


    let mut out_len = out_txt_box.len() as size_t;
    let out_txt_len = Box::new(&mut out_len);
    unsafe {
        trace!("private_key.len:{}", private_len);
        match asymmetric_decrypt(
            input.as_ptr(),
            input.len() as size_t,
            private_key.as_ptr(),
            private_len as size_t,
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
                error!("Error: symmetric decrypt failed :{}, \n pri_key: {}, \n input : {} ", i, hex::encode(&private_key.as_bytes()), hex::encode(&input));

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

    let pk_len = pk.len();
    let sec_len = sec_key.len();
    let pk = CString::new(pk).unwrap();
    let sec_key = CString::new(sec_key).unwrap();
    unsafe {
        match sign(
            plain_txt.as_ptr(),
            plain_txt.len() as size_t,
            id.as_ptr() as *const i8,
            id.as_bytes().len() as size_t,
            pk.as_ptr(),
            pk_len as size_t,
            sec_key.as_ptr(),
            sec_len as size_t,
            out_txt_box.as_mut_ptr(),
            *out_txt_len_box,
            asymmetric_cryptograph_t_SM2,
        ) {
            0 => {}
            i => {
                error!("Error:  sig_SM2 failed :{}, \n pri_key: {}, \n pk:{}, \n input : {} ", i, hex::encode(&sec_key.as_bytes()), hex::encode(&pk.as_bytes()), hex::encode(&plain_txt));

            }
        };
    }

    let split_index_usize: usize = out_txt_len_box.to_owned() as usize;
    out_txt_box.split_at_mut(split_index_usize).0.to_vec()
}


pub fn verify_SM2(plain_txt: &[u8], signature:&[u8], pk: &[u8]) -> i32 {
    let id = "123".to_string();

    let pk_len = pk.len();
    let pk = CString::new(pk).unwrap();
    unsafe {
        trace!("pk.len:{}", pk_len);
        verify(
            plain_txt.as_ptr(),
            plain_txt.len() as size_t,
            id.as_ptr() as *const i8,
            id.as_bytes().len() as size_t,
            signature.as_ptr(),
            signature.len() as size_t,
            pk.as_ptr(),
            pk_len as size_t,
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
        let text1  = plain_from_server();
        let text2 = String::from(&text1);
        println!("text1 == text2, {}", &text1.eq(&text2));
        let signature1 = sig_SM2(plain_from_server().as_bytes(), enckey.as_slice(), pk.as_slice());
        let signature2 = sig_SM2((&text2).as_bytes(), enckey.as_slice(), pk.as_slice());

        println!("signature1: {}", hex::encode(&signature1));
        println!("signature2: {}", hex::encode(&signature2));
        let result1 = verify_SM2(&text1.as_bytes(), signature1.as_slice(), pk.as_slice());
        let result2 = verify_SM2(&text2.as_bytes(), signature2.as_slice(), pk.as_slice());
        println!("result1: {} , result2: {}", result1, result2);

    }

    #[test]
    fn test_bug() {
        let (enckey, pk) = use_const_pk();
        let text1 = "30820436022100f1733f059918ae3ac74aadbbcbfd17d249b88a4456553d7fd3c5107bd2662e16022046df1757a418c0acf9516a50a7ee1b9dfedafd3416379706589b0d4d4523dcb9042056b248a24aaa8c83d99637eeb6ae8ad09935e70e112c053a4f530ebe1a7ea786048203cb4d5224ab61614af89d2a0f6b933e77ace154e4127bad9724c4ca1e8ed847bab5ed226cf56359604a07dc9a84580ca563714652dfde22dded22e2042e43f707a1a9ac9ce42d190dd74d32b8285a9ac1ad4f58f6dc84d5fd49de395e58109c181872b3394fe78702bd7f033f80b0da2617d4620e7e129d07b42210452997694a490b43e5664fdf00b6c17336d0a266cfbaa82b5ce7d60db0c172d402df2d60712473ac32a5bd17a7b14ef1af39f0164577149b41075e338489ad091aedcf977f046c5b8430c15fa170db4f49214a160b0504f066fb5373278d1a5dcee62c9a607ad2365407f5de881e3b3bc2fc3e424bfa0d2bbb955295828a24e8aa5cc6735528c12d135bbb20647b2a78e19eaf77b0feed6592c73d10f64a3a9a7ccde5c6d2be6110a4770472c11754464283e99543af200d75757e78f8d8d9cb6f3e7a68053e9533b8a67d48bf41594fe004cab9064757c0cd4cdf789a0e029ce48c18b450a383ade404c3ddb199d29cb39785cb78f7c1a044b6f34ce37fb4bb0b4bfb47928276e74d1581b540b03b859a3b6c67ac6de1ee1b60062d19ee9125d03111d3609b7f169817b8007e4aa1d719c562468e8970710f1e83399476ac039fa4ae9c3f7c7746e6f68a4dc6aa261edc38c6f0a4c4607769c79bbbd7c007cbc2a2e710281ed486010bbf401dc65b6ac79e9c1a7237a504034869ecdc8fb40eb8b33ae63d20a48d08c5d8d828cbe07b71a8f3eb4598f4821d303f85de35771965cdb2c7c79782a4350964026db6fe531f21c4ef676c10ac8d66f70f185be179f46382856b95826f2a34cab946322dbaf175bd7230bc4d24f6a0c62673088ef10d7a320fd93676f174717b0644e383444c4aa3f6d6ed441c44f0b574831569663389d531ee10311997c10e4d3e33696874554c9fcf43ff302c6ccd4eca5048ae2751780839c67e70c57f72422ef1a63956046caaaceec9a5fdd6da3d705034ba530c2eb57f5ce37558421277d2a610173153edd677cd899561bd8c99a68a123f4065fe873778ab181900cf8b336c378ca1d7172547cebd0d8acb925fbbb1687748e10f00678a0830ce9754facbfe08b70700a6d0882966a0052edce57903972ddb41f4e9f91261f1316c3d977bc3c35f9b716cce9b0b8ab2d94c2963e18e40eedb9d0c290af94b6439b6aab696c588763a33a4afa8c8caaf18d742a980049cd6da2d82eaa33da3b32081561e167b2e63af7590ab3b03cbfba027075eac2ed4a769594f4ec6589cd9eaae45fe031976134255311a73eef6aba255970b6ea9a628d50c6405c6d39bc1381207fe5b3bb3b12cea05a1a524c50915c186894ad1eb75128fb654f1fa696ee0e1f88093b275662c".to_string();
        //
        // let text2 = String::from(&text1);
        // println!("text1 == text2, {}", &text1.eq(&text2));
        // let signature1 = sig_SM2(plain_from_server().as_bytes(), enckey.as_slice(), pk.as_slice());

        // let signature2 = sig_SM2(text1.as_bytes(), enckey.as_slice(), pk.as_slice());

        let string1 = plain_from_server();
        let signature1 = sig_SM2(string1.as_bytes(), enckey.as_slice(), pk.as_slice());




        // let signature2 = sig_SM2(text1.as_bytes(), enckey.as_slice(), pk.as_slice());

        println!("signature1: {}", hex::encode(&signature1));
        // println!("signature2: {}", hex::encode(&signature2));
        // let result1 = verify_SM2(&text1.as_bytes(), signature1.as_slice(), pk.as_slice());
        // let result2 = verify_SM2(&text2.as_bytes(), signature2.as_slice(), pk.as_slice());
        // println!("result1: {} , result2: {}", result1, result2);
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
    fn test_asymmetric_encrypt_SM2_only() {

        let sec = "36306565633565346163623339313830373437316532643038653338356131623132376561326633336635393662613732326564653634346530346535656535";
        let sec = hex::decode(sec).unwrap();
        let output = "3081d3022074a64cc2d926da3baa5d98a0b6b51fe25cb5411f141711c48ce103544d4b52fd02207787ba7f78b17f305398206f233debefe395e71f35373c621d66cc460b7c96670420a7dc164201717e66de8568ddfb2d36dceda5f93a54c3c880674d5b1c608d4bd0046bcc9b10ef2b662e32b673e72bcd5f485658f42c26e97dd0cff71e3a26ecbe92de4a86265ded68e20ecf045334a20d4151274859e897511e2c769bcdb95deb62d1bf6b62d767dfacce93647de9f4eaae84ed6aff2b5cfed30446da260e2d633a4d645d789e76c617a692ed89";
        let output = hex::decode(output).unwrap();
        let outPlaintext2 = asymmetric_decrypt_SM2(output.as_slice(), sec.as_slice()).unwrap();
        println!("outPlaintext2:{}", hex::encode(&outPlaintext2));

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
        let hex1 = "30820436022100f1733f059918ae3ac74aadbbcbfd17d249b88a4456553d7fd3c5107bd2662e16022046df1757a418c0acf9516a50a7ee1b9dfedafd3416379706589b0d4d4523dcb9042056b248a24aaa8c83d99637eeb6ae8ad09935e70e112c053a4f530ebe1a7ea786048203cb4d5224ab61614af89d2a0f6b933e77ace154e4127bad9724c4ca1e8ed847bab5ed226cf56359604a07dc9a84580ca563714652dfde22dded22e2042e43f707a1a9ac9ce42d190dd74d32b8285a9ac1ad4f58f6dc84d5fd49de395e58109c181872b3394fe78702bd7f033f80b0da2617d4620e7e129d07b42210452997694a490b43e5664fdf00b6c17336d0a266cfbaa82b5ce7d60db0c172d402df2d60712473ac32a5bd17a7b14ef1af39f0164577149b41075e338489ad091aedcf977f046c5b8430c15fa170db4f49214a160b0504f066fb5373278d1a5dcee62c9a607ad2365407f5de881e3b3bc2fc3e424bfa0d2bbb955295828a24e8aa5cc6735528c12d135bbb20647b2a78e19eaf77b0feed6592c73d10f64a3a9a7ccde5c6d2be6110a4770472c11754464283e99543af200d75757e78f8d8d9cb6f3e7a68053e9533b8a67d48bf41594fe004cab9064757c0cd4cdf789a0e029ce48c18b450a383ade404c3ddb199d29cb39785cb78f7c1a044b6f34ce37fb4bb0b4bfb47928276e74d1581b540b03b859a3b6c67ac6de1ee1b60062d19ee9125d03111d3609b7f169817b8007e4aa1d719c562468e8970710f1e83399476ac039fa4ae9c3f7c7746e6f68a4dc6aa261edc38c6f0a4c4607769c79bbbd7c007cbc2a2e710281ed486010bbf401dc65b6ac79e9c1a7237a504034869ecdc8fb40eb8b33ae63d20a48d08c5d8d828cbe07b71a8f3eb4598f4821d303f85de35771965cdb2c7c79782a4350964026db6fe531f21c4ef676c10ac8d66f70f185be179f46382856b95826f2a34cab946322dbaf175bd7230bc4d24f6a0c62673088ef10d7a320fd93676f174717b0644e383444c4aa3f6d6ed441c44f0b574831569663389d531ee10311997c10e4d3e33696874554c9fcf43ff302c6ccd4eca5048ae2751780839c67e70c57f72422ef1a63956046caaaceec9a5fdd6da3d705034ba530c2eb57f5ce37558421277d2a610173153edd677cd899561bd8c99a68a123f4065fe873778ab181900cf8b336c378ca1d7172547cebd0d8acb925fbbb1687748e10f00678a0830ce9754facbfe08b70700a6d0882966a0052edce57903972ddb41f4e9f91261f1316c3d977bc3c35f9b716cce9b0b8ab2d94c2963e18e40eedb9d0c290af94b6439b6aab696c588763a33a4afa8c8caaf18d742a980049cd6da2d82eaa33da3b32081561e167b2e63af7590ab3b03cbfba027075eac2ed4a769594f4ec6589cd9eaae45fe031976134255311a73eef6aba255970b6ea9a628d50c6405c6d39bc1381207fe5b3bb3b12cea05a1a524c50915c186894ad1eb75128fb654f1fa696ee0e1f88093b275662c".to_string();
        let hex2 = hex1.clone();
        println!("{}", hex1);
        hex2
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
    fn test_1()  {
        // let enckey = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
        //     .as_bytes().to_vec();
        // let pk = "0409F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13"
        //     .as_bytes().to_vec();

        let enckey = hex::decode("33393435323038463742323134344231334633364533384143364433394639353838393339333639323836304235314134324642383145463444463743354238".as_bytes()).unwrap().to_owned();
        let pk = hex::decode("30343039463944463331314535343231413135304444374431363145344243354336373231373946414431383333464330373642423038464633353646333530323043434541343930434532363737354135324443364541373138434331414136303041454430354642463335453038344136363332463630373244413941443133".as_bytes()).unwrap().to_owned();
        println!("enckey: {:?}", String::from_utf8(enckey));
        println!("pk: {:?}", String::from_utf8(pk));


        // (enckey, pk)
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
