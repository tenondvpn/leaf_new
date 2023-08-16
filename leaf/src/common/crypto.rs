use std::collections::HashMap;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use bytes::BytesMut;

use std::ffi::CString;
use std::ptr::null;
use std::mem;
use std::str;
use std::slice;
use crate::common;

pub struct SM4Key {
    pub rk: [u32; 32],
}

impl SM4Key{
    pub fn new() -> SM4Key{
        SM4Key{
           rk: unsafe {mem::uninitialized()},
        }
    }
}

#[link(name="gmssl")]
extern "C" {
    fn add(key: *const SM4Key, a: i32, b: i32, data: *mut i8, len: usize) -> i32;
    fn sm4_set_encrypt_key(key: *mut SM4Key, raw_key: *const u8);
    fn sm4_gcm_encrypt(key: *const SM4Key, iv: *const u8, ivlen: usize,
        aad: *const u8, aadlen: usize, in1: *const u8, inlen: usize,
        out: *const u8, taglen: usize, tag: *const u8) -> i32;
    fn sm4_gcm_decrypt(key: *const SM4Key, iv: *const u8, ivlen: usize,
        aad: *const u8, aadlen: usize, in1: *const u8, inlen: usize,
        tag: *const u8, taglen: usize, out: *const u8) -> i32;
}

pub trait Cipher<N>: Sync + Send + Unpin
    where
        N: NonceSequence,
{
    type Enc;
    type Dec;

    fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc>;
    fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec>;
}

pub trait SizedCipher {
    fn key_len(&self) -> usize;
    fn nonce_len(&self) -> usize;

    fn tag_len(&self) -> usize {
        // All AEAD ciphers we support use 128-bit tags.
        16
    }
}

pub trait Encryptor: Sync + Send + Unpin {
    fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>;
}

pub trait Decryptor: Sync + Send + Unpin {
    fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
        where
            InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>;
}

pub trait NonceSequence: Sync + Send + Unpin {
    fn advance(&mut self) -> Result<Vec<u8>>;
}

#[cfg(feature = "openssl-aead")]
pub mod aead {
    use openssl::symm;

    use super::*;

    lazy_static! {
        static ref AEAD_LIST: HashMap<&'static str, symm::Cipher> = {
            let mut m = HashMap::new();
            m.insert("chacha20-poly1305", symm::Cipher::chacha20_poly1305());
            m.insert("chacha20-ietf-poly1305", symm::Cipher::chacha20_poly1305());
            m.insert("aes-256-gcm", symm::Cipher::aes_256_gcm());
            m.insert("aes-128-gcm", symm::Cipher::aes_128_gcm());
            m.insert("sm4-gcm", symm::Cipher::aes_128_gcm());
            m
        };
    }

    pub struct AeadCipher {
        cipher: symm::Cipher,
        cipher_name: String,
    }

    impl AeadCipher {
        pub fn new(cipher: &str) -> Result<Self> {
            let alg = match AEAD_LIST.get(cipher) {
                Some(v) => v,
                None => return Err(anyhow!("unsupported cipher: {}", cipher)),
            };
            Ok(AeadCipher {
                cipher: *alg,
                cipher_name: cipher.to_string(),
            })
        }
    }

    impl<N> Cipher<N> for AeadCipher
        where
            N: 'static + NonceSequence,
    {
        type Enc = AeadEncryptor<N>;
        type Dec = AeadDecryptor<N>;

        fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc> {
            Ok(AeadEncryptor::new(
                self.cipher,
                key.to_vec(),
                nonce,
                self.tag_len(),
                self.cipher_name.clone(),
            ))
        }

        fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec> {
            Ok(AeadDecryptor::new(
                self.cipher,
                key.to_vec(),
                nonce,
                self.tag_len(),
                self.cipher_name.clone(),
            ))
        }
    }

    impl SizedCipher for AeadCipher {
        fn key_len(&self) -> usize {
            self.cipher.key_len()
        }

        fn nonce_len(&self) -> usize {
            // All AEAD ciphers use IV.
            self.cipher.iv_len().unwrap()
        }
    }

    pub struct AeadEncryptor<N> {
        cipher_name: String,
        cipher: symm::Cipher,
        key: Vec<u8>,
        nonce: N,
        tag_len: usize,
        sm4_key: SM4Key,
    }

    impl<N> AeadEncryptor<N>
        where
            N: NonceSequence,
    {
        pub fn new(cipher: symm::Cipher, key: Vec<u8>, nonce: N, tag_len: usize, cipher_name: String) -> Self {
            let mut sm4_key = SM4Key::new();
            let raw_mut_sm4key = &mut sm4_key as *mut SM4Key;
            unsafe {
                sm4_set_encrypt_key(raw_mut_sm4key, key.as_ptr());
            }

            AeadEncryptor {
                cipher_name,
                cipher,
                key,
                nonce,
                tag_len,
                sm4_key,
            }
        }
    }

    impl<N> Encryptor for AeadEncryptor<N>
        where
            N: NonceSequence,
    {
        fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
            where
                InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            let mut tag = vec![0u8; self.tag_len];
            // TODO in-place?
            if self.cipher_name.eq("sm4-gcm") {
                let plain_txt = in_out.as_ref();
                let mut out_vec = vec![1u8; plain_txt.len()];
                unsafe {
                    let res_size = sm4_gcm_encrypt(
                        &self.sm4_key,
                        nonce.as_ptr(),
                        nonce.len() as usize,
                        nonce.as_ptr(),
                        0,
                        plain_txt.as_ptr(),
                        plain_txt.len() as usize,
                        out_vec.as_ptr(),
                        16,
                        tag.as_ptr());
                    if (res_size != 1) {
                        panic!("sm4 gcm encrypt failed!");
                    }
                }

                (&mut in_out.as_mut()[..out_vec.len()]).copy_from_slice(&out_vec);
                in_out.extend(&tag);
            } else {
                let ciphertext = symm::encrypt_aead(
                    self.cipher,
                    &self.key,
                    Some(&nonce),
                    &[],
                    in_out.as_ref(),
                    &mut tag,
                ).map_err(|e| anyhow!("encrypt failed: {}", e))?;
                (&mut in_out.as_mut()[..ciphertext.len()]).copy_from_slice(&ciphertext);
                in_out.extend(&tag);
            };
            Ok(())
        }
    }

    pub struct AeadDecryptor<N> {
        cipher_name: String,
        cipher: symm::Cipher,
        key: Vec<u8>,
        nonce: N,
        tag_len: usize,
        sm4_key: SM4Key,
    }

    impl<N> AeadDecryptor<N>
        where
            N: NonceSequence,
    {
        pub fn new(cipher: symm::Cipher, key: Vec<u8>, nonce: N, tag_len: usize, cipher_name: String) -> Self {
            let mut sm4_key = SM4Key::new();
            let raw_mut_sm4key = &mut sm4_key as *mut SM4Key;
            unsafe {
                sm4_set_encrypt_key(raw_mut_sm4key, key.as_ptr());
            }
            AeadDecryptor {
                cipher_name,
                cipher,
                key,
                nonce,
                tag_len,
                sm4_key,
            }
        }
    }

    impl<N> Decryptor for AeadDecryptor<N>
        where
            N: NonceSequence,
    {
        fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
            where
                InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("decrypt failed: {}", e))?;
            // TODO in-place?
            if self.cipher_name.eq("sm4-gcm") {
                let in_out_ref = in_out.as_ref();
                let data = &in_out_ref[..in_out_ref.len() - self.tag_len];
                let tag = &in_out_ref[in_out_ref.len() - self.tag_len..];
                let mut out_vec = vec![1u8; data.len()];
                unsafe {
                    let dec_size = sm4_gcm_decrypt(
                        &self.sm4_key,
                        nonce.as_ptr(),
                        nonce.len() as usize,
                        nonce.as_ptr(),
                        0,
                        data.as_ptr(),
                        data.len() as usize,
                        tag.as_ptr(),
                        16,
                        out_vec.as_ptr());
                }

                (&mut in_out.as_mut()[..out_vec.len()]).copy_from_slice(&out_vec);
            } else {
                let in_out_ref = in_out.as_ref();
                let data = &in_out_ref[..in_out_ref.len() - self.tag_len];
                let tag = &in_out_ref[in_out_ref.len() - self.tag_len..];
                let tmp_plaintext = symm::decrypt_aead(self.cipher, &self.key, Some(&nonce), &[], data, tag)
                    .map_err(|e| anyhow!("decrypt failed: {}", e))?;
                (&mut in_out.as_mut()[..tmp_plaintext.len()]).copy_from_slice(&tmp_plaintext);
            };

            Ok(())
        }
    }
}

#[cfg(feature = "ring-aead")]
pub mod aead {
    use ring::aead::{self, Aad, Algorithm, LessSafeKey, Nonce, UnboundKey};

    use super::*;

    lazy_static! {
        static ref AEAD_LIST: HashMap<&'static str, &'static Algorithm> = {
            let mut m = HashMap::new();
            m.insert("chacha20-poly1305", &aead::CHACHA20_POLY1305);
            m.insert("chacha20-ietf-poly1305", &aead::CHACHA20_POLY1305);
            m.insert("aes-256-gcm", &aead::AES_256_GCM);
            m.insert("aes-128-gcm", &aead::AES_128_GCM);
            m.insert("sm4-gcm", &aead::AES_128_GCM);
            m
        };
    }

    pub struct AeadCipher {
        algorithm: &'static Algorithm,
    }

    impl AeadCipher {
        pub fn new(cipher: &str) -> Result<Self> {
            let alg = match AEAD_LIST.get(cipher) {
                Some(v) => v,
                None => return Err(anyhow!("unsupported cipher: {}", cipher)),
            };
            Ok(AeadCipher { algorithm: alg })
        }
    }

    impl<N> Cipher<N> for AeadCipher
        where
            N: 'static + NonceSequence,
    {
        type Enc = AeadEncryptor<N>;
        type Dec = AeadDecryptor<N>;

        fn encryptor(&self, key: &[u8], nonce: N) -> Result<Self::Enc> {
            let unbound_key = UnboundKey::new(self.algorithm, key)
                .map_err(|e| anyhow!("new unbound key failed: {}", e))?;
            let enc = AeadEncryptor {
                enc: LessSafeKey::new(unbound_key),
                nonce,
            };
            Ok(enc)
        }

        fn decryptor(&self, key: &[u8], nonce: N) -> Result<Self::Dec> {
            let unbound_key = UnboundKey::new(self.algorithm, key)
                .map_err(|e| anyhow!("new unbound key failed: {}", e))?;
            let enc = AeadDecryptor {
                enc: LessSafeKey::new(unbound_key),
                nonce,
            };
            Ok(enc)
        }
    }

    impl SizedCipher for AeadCipher {
        fn key_len(&self) -> usize {
            self.algorithm.key_len()
        }

        fn nonce_len(&self) -> usize {
            self.algorithm.nonce_len()
        }
    }

    pub struct AeadEncryptor<N> {
        enc: LessSafeKey,
        nonce: N,
    }

    impl<N> AeadEncryptor<N>
        where
            N: NonceSequence,
    {
        pub fn new(enc: LessSafeKey, nonce: N) -> Self {
            AeadEncryptor { enc, nonce }
        }
    }

    impl<N> Encryptor for AeadEncryptor<N>
        where
            N: NonceSequence,
    {
        fn encrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
            where
                InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            let nonce = Nonce::try_assume_unique_for_key(&nonce)
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            self.enc
                .seal_in_place_append_tag(nonce, Aad::empty(), in_out)
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            Ok(())
        }
    }

    pub struct AeadDecryptor<N> {
        enc: LessSafeKey,
        nonce: N,
    }

    impl<N> AeadDecryptor<N>
        where
            N: NonceSequence,
    {
        pub fn new(enc: LessSafeKey, nonce: N) -> Self {
            AeadDecryptor { enc, nonce }
        }
    }

    impl<N> Decryptor for AeadDecryptor<N>
        where
            N: NonceSequence,
    {
        fn decrypt<InOut>(&mut self, in_out: &mut InOut) -> Result<()>
            where
                InOut: AsRef<[u8]> + AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
        {
            let nonce = self
                .nonce
                .advance()
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            let nonce = Nonce::try_assume_unique_for_key(&nonce)
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            self.enc
                .open_within(nonce, Aad::empty(), in_out.as_mut(), 0..)
                .map_err(|e| anyhow!("encrypt failed: {}", e))?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sm4_aead_enc_dec() {
        unsafe {
            let mut hello = String::from("Hello, ");
            let len = hello.len();
            let format = CString::new(hello).unwrap();
            let mut raw_str = format.into_raw();
            let mut param=SM4Key::new();
            let mut key = String::from("1234567890123456");
            let mut iv = String::from("1234567890123456");
            let mut tag = String::from("1234567890123456");

            let raw_mut_sm4key = &mut param as *mut SM4Key;
            sm4_set_encrypt_key(raw_mut_sm4key, key.as_ptr());

            let mut plain_txt = String::from("plain text");
            let mut dec_txt = String::from("xxxxx ixxx");
            let mut out_txt = String::from("plain text");
            let out_txt_cstr = CString::new(out_txt).unwrap();
            let mut out_raw_txt = out_txt_cstr.into_raw() as *mut u8;
            let tag_cstr = CString::new(tag).unwrap();
            let mut tag_raw = tag_cstr.into_raw() as *mut u8;
            let mut dec_txt_cstr = CString::new(dec_txt).unwrap();
            let mut dec_raw = dec_txt_cstr.into_raw() as *mut u8;

            let res_size = sm4_gcm_encrypt(&param, iv.as_ptr(), iv.len() as usize, iv.as_ptr(), 0, plain_txt.as_ptr(), plain_txt.len() as usize, out_raw_txt, 16, tag_raw);
            let dec_size = sm4_gcm_decrypt(&param, iv.as_ptr(), iv.len() as usize, iv.as_ptr(), 0, out_raw_txt, plain_txt.len() as usize, tag_raw, 16, dec_raw);

            let dec_raw_cstr = CString::from_raw(dec_raw as *mut i8);
            let dec_str: &str = dec_raw_cstr.to_str().unwrap();
            let dec_str_buf: String = dec_str.to_owned();
            println!("dec str: {}", dec_str_buf);
        }
    }

    //#[cfg(any(feature = "openssl-aead"))]
    fn test_aead_enc_dec() {
        struct ShadowsocksNonceSequence(Vec<u8>);

        impl ShadowsocksNonceSequence {
            fn new(size: usize) -> Self {
                let mut c = Vec::new();
                for _ in 0..size {
                    c.push(0xff);
                }
                ShadowsocksNonceSequence(c)
            }

            fn inc(&mut self) {
                for x in &mut self.0 {
                    *x = (*x).wrapping_add(1);
                    if *x != 0 {
                        return;
                    }
                }
            }
        }

        impl NonceSequence for ShadowsocksNonceSequence {
            fn advance(&mut self) -> Result<Vec<u8>> {
                self.inc();
                Ok(self.0.clone())
            }
        }
        let plaintext = b"Hello, world!";

        for method_name in ["chacha20-poly1305", "chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm", "sm4-gcm"].iter() {
            let cipher = aead::AeadCipher::new(method_name).unwrap();
            let key = vec![0u8; cipher.key_len()];

            let mut buf = Vec::new();
            buf.extend_from_slice(plaintext);

            let nonce = ShadowsocksNonceSequence::new(cipher.nonce_len());
            let mut enc = cipher.encryptor(&key, nonce).unwrap();
            enc.encrypt(&mut buf).unwrap();

            let dec_nonce = ShadowsocksNonceSequence::new(cipher.nonce_len());
            let mut dec = cipher.decryptor(&key, dec_nonce).unwrap();
            dec.decrypt(&mut buf).unwrap();

            assert_eq!(&buf[..plaintext.len()], plaintext);
            println!("{} success", method_name);
        }

    }
}
