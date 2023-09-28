use anyhow::anyhow;
use anyhow::Result;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;

use crate::common::crypto::NonceSequence;

pub struct ShadowsocksNonceSequence(Vec<u8>);

impl ShadowsocksNonceSequence {
    pub fn new(size: usize) -> Self {
        ShadowsocksNonceSequence(vec![0xff; size])
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

pub fn kdf(pass: &[u8], size: usize) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    let mut sum = Md5::digest(pass).to_vec();
    std::io::Write::write(&mut key, &sum)?;
    while key.len() < size {
        sum = Md5::digest(&[sum, pass.to_vec()].concat()).to_vec();
        std::io::Write::write(&mut key, &sum)?;
    }
    Ok(key)
}

pub fn hkdf_sha1(key: &[u8], salt: &[u8], info: Vec<u8>, size: usize) -> Result<Vec<u8>> {
    let (_, h) = Hkdf::<Sha1>::extract(Some(salt), key);
    let mut okm = vec![0u8; size];
    h.expand(&info, &mut okm)
        .map_err(|_| anyhow!("hkdf expand failed"))?;
    Ok(okm.to_vec())
}

#[test]
fn test_psk() {
    let psk = kdf(
        "ea7d5bd1c0975e8efe3ad19471605a7123346dc3b2fca87171ec765a099168bc".as_bytes(),
        16,
    )
    .unwrap();
    println!("psk: {:?}", psk);
}
