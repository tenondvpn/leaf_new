use std::collections::HashMap;

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use bytes::BytesMut;

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
            m.insert("sm4_cbc", symm::Cipher::sm4_cbc());
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
    }

    impl<N> AeadEncryptor<N>
        where
            N: NonceSequence,
    {
        pub fn new(cipher: symm::Cipher, key: Vec<u8>, nonce: N, tag_len: usize, cipher_name: String) -> Self {
            AeadEncryptor {
                cipher_name,
                cipher,
                key,
                nonce,
                tag_len,
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
            if self.cipher_name.eq("sm4_cbc") {
                let ciphertext =  symm::encrypt(self.cipher, &self.key, Some(&nonce), in_out.as_ref())
                    .map_err(|e| anyhow!("use {} encrypt failed: {}",self.cipher_name, e))?;
                // 扩展 in_out 的容量来适应密文长度
                let extend_size = ciphertext.len() - in_out.as_mut().len();
                if extend_size > 0 {
                    in_out.extend(&vec![0u8; extend_size]);
                }
                (&mut in_out.as_mut()[..ciphertext.len()]).copy_from_slice(&ciphertext);
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
    }

    impl<N> AeadDecryptor<N>
        where
            N: NonceSequence,
    {
        pub fn new(cipher: symm::Cipher, key: Vec<u8>, nonce: N, tag_len: usize, cipher_name: String) -> Self {
            AeadDecryptor {
                cipher_name,
                cipher,
                key,
                nonce,
                tag_len,
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
            let plaintext = if self.cipher_name.eq("sm4_cbc") {
                symm::decrypt(self.cipher, &self.key, Some(&nonce), in_out.as_ref()).map_err(
                    |e| anyhow!("use {} decrypt failed: {}", self.cipher_name, e))?
            } else {
                let in_out_ref = in_out.as_ref();
                let data = &in_out_ref[..in_out_ref.len() - self.tag_len];
                let tag = &in_out_ref[in_out_ref.len() - self.tag_len..];
                symm::decrypt_aead(self.cipher, &self.key, Some(&nonce), &[], data, tag)
                    .map_err(|e| anyhow!("decrypt failed: {}", e))?
            };


            (&mut in_out.as_mut()[..plaintext.len()]).copy_from_slice(&plaintext);
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
    #[cfg(any(feature = "openssl-aead"))]
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

        for method_name in ["chacha20-poly1305", "chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm", "sm4_cbc"].iter() {
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
