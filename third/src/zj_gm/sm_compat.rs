use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use foreign_types::{ForeignType, ForeignTypeRef};
use libc::size_t;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::symm::{decrypt_aead, encrypt_aead, Cipher};
use openssl_sys as ffi;

use super::bindings::{
    asymmetric_cryptograph_t, asymmetric_cryptograph_t_SM2, padding_t, signature_algorithm_t,
    signature_algorithm_t_SM2_SIGN, symmetric_cryptograph_t, symmetric_cryptograph_t_SM4,
};

const SM3_IV: [u32; 8] = [
    0x7380_166f,
    0x4914_b2b9,
    0x1724_42d7,
    0xda8a_0600,
    0xa96f_30bc,
    0x1631_38aa,
    0xe38d_ee4d,
    0xb0fb_0e4e,
];

extern "C" {
    fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut ffi::EVP_MD_CTX, pctx: *mut ffi::EVP_PKEY_CTX);
    fn EVP_PKEY_CTX_set1_id(
        ctx: *mut ffi::EVP_PKEY_CTX,
        id: *const c_void,
        len: c_int,
    ) -> c_int;
}

fn bytes_from_ptr<'a, T>(ptr: *const T, len: size_t) -> Option<&'a [T]> {
    if ptr.is_null() && len != 0 {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(ptr, len as usize) })
}

fn bytes_from_mut_ptr<'a, T>(ptr: *mut T, len: size_t) -> Option<&'a mut [T]> {
    if ptr.is_null() && len != 0 {
        return None;
    }
    Some(unsafe { slice::from_raw_parts_mut(ptr, len as usize) })
}

fn ascii_key(ptr: *const c_char, len: size_t) -> Result<Vec<u8>, ErrorStack> {
    if ptr.is_null() {
        return Err(ErrorStack::get());
    }

    let bytes = if len == 0 {
        unsafe { CStr::from_ptr(ptr).to_bytes() }
    } else {
        unsafe { slice::from_raw_parts(ptr as *const u8, len as usize) }
    };

    Ok(bytes.to_vec())
}

fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    hex::encode(bytes).into_bytes()
}

fn decode_ascii_hex(bytes: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let text = std::str::from_utf8(bytes).map_err(|_| ErrorStack::get())?;
    hex::decode(text).map_err(|_| ErrorStack::get())
}

fn sm2_group() -> Result<EcGroup, ErrorStack> {
    EcGroup::from_curve_name(Nid::SM2)
}

fn pkey_from_public_ascii(public_key: &[u8]) -> Result<PKey<Public>, ErrorStack> {
    let group = sm2_group()?;
    let mut ctx = BigNumContext::new()?;
    let raw_public_key = decode_ascii_hex(public_key)?;
    let point = EcPoint::from_bytes(&group, &raw_public_key, &mut ctx)?;
    let ec_key = EcKey::from_public_key(&group, &point)?;
    let pkey = PKey::from_ec_key(ec_key)?;
    if pkey.id() != Id::SM2 {
        return Err(ErrorStack::get());
    }
    Ok(pkey)
}

fn pkey_from_private_ascii(private_key: &[u8]) -> Result<PKey<Private>, ErrorStack> {
    let group = sm2_group()?;
    let private_key = decode_ascii_hex(private_key)?;
    let private_bn = BigNum::from_slice(&private_key)?;
    let mut ctx = BigNumContext::new()?;
    let mut public_point = EcPoint::new(&group)?;
    public_point.mul_generator(&group, &private_bn, &ctx)?;
    let ec_key = EcKey::from_private_components(&group, &private_bn, &public_point)?;
    let pkey = PKey::from_ec_key(ec_key)?;
    if pkey.id() != Id::SM2 {
        return Err(ErrorStack::get());
    }
    Ok(pkey)
}

fn copy_output(src: &[u8], output: *mut u8, output_len: *mut size_t) -> c_int {
    if output_len.is_null() {
        return 1;
    }

    let capacity = unsafe { *output_len as usize };
    unsafe {
        *output_len = src.len() as size_t;
    }

    if output.is_null() {
        return 0;
    }

    if capacity < src.len() {
        return 1;
    }

    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), output, src.len());
    }
    0
}

fn set_sm2_id<T>(
    ctx: &mut openssl::pkey_ctx::PkeyCtxRef<T>,
    id: *const c_char,
    id_len: size_t,
) -> c_int {
    let id_ptr = if id.is_null() || id_len == 0 {
        ptr::null()
    } else {
        id as *const c_void
    };

    unsafe { EVP_PKEY_CTX_set1_id(ctx.as_ptr(), id_ptr, id_len as c_int) }
}

fn sm4_gcm_cipher() -> Result<Cipher, ErrorStack> {
    Cipher::from_nid(Nid::from_raw(1248)).ok_or_else(ErrorStack::get)
}

fn sm4_gcm_encrypt(
    input: &[u8],
    output: &mut [u8],
    tag: &mut [u8],
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> c_int {
    if key.len() != 16 || output.len() < input.len() || tag.is_empty() {
        return 1;
    }

    let result = (|| -> Result<Vec<u8>, ErrorStack> {
        let cipher = sm4_gcm_cipher()?;
        encrypt_aead(cipher, key, Some(iv), aad, input, tag)
    })();

    match result {
        Ok(encrypted) if encrypted.len() == input.len() => {
            output[..encrypted.len()].copy_from_slice(&encrypted);
            0
        }
        _ => 1,
    }
}

fn sm4_gcm_decrypt(
    input: &[u8],
    output: &mut [u8],
    tag: &[u8],
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
) -> c_int {
    if key.len() != 16 || output.len() < input.len() {
        return 1;
    }

    let result = (|| -> Result<Vec<u8>, ErrorStack> {
        let cipher = sm4_gcm_cipher()?;
        decrypt_aead(cipher, key, Some(iv), aad, input, tag)
    })();

    match result {
        Ok(decrypted) if decrypted.len() == input.len() => {
            output[..decrypted.len()].copy_from_slice(&decrypted);
            0
        }
        _ => 1,
    }
}

fn sm3_p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

fn sm3_p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

fn sm3_ff(x: u32, y: u32, z: u32, round: usize) -> u32 {
    if round < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

fn sm3_gg(x: u32, y: u32, z: u32, round: usize) -> u32 {
    if round < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (!x & z)
    }
}

fn sm3_compress(ctx: &mut super::bindings::sm3_ctx_t, block: &[u8; 64]) {
    let mut w = [0u32; 68];
    let mut w1 = [0u32; 64];

    for (index, chunk) in block.chunks_exact(4).enumerate() {
        w[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    for index in 16..68 {
        w[index] = sm3_p1(w[index - 16] ^ w[index - 9] ^ w[index - 3].rotate_left(15))
            ^ w[index - 13].rotate_left(7)
            ^ w[index - 6];
    }

    for index in 0..64 {
        w1[index] = w[index] ^ w[index + 4];
    }

    let mut a = ctx.digest[0];
    let mut b = ctx.digest[1];
    let mut c = ctx.digest[2];
    let mut d = ctx.digest[3];
    let mut e = ctx.digest[4];
    let mut f = ctx.digest[5];
    let mut g = ctx.digest[6];
    let mut h = ctx.digest[7];

    for round in 0..64 {
        let t: u32 = if round < 16 { 0x79cc_4519 } else { 0x7a87_9d8a };
        let ss1 = a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(t.rotate_left(round as u32))
            .rotate_left(7);
        let ss2 = ss1 ^ a.rotate_left(12);
        let tt1 = sm3_ff(a, b, c, round)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w1[round]);
        let tt2 = sm3_gg(e, f, g, round)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[round]);

        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = sm3_p0(tt2);
    }

    ctx.digest[0] ^= a;
    ctx.digest[1] ^= b;
    ctx.digest[2] ^= c;
    ctx.digest[3] ^= d;
    ctx.digest[4] ^= e;
    ctx.digest[5] ^= f;
    ctx.digest[6] ^= g;
    ctx.digest[7] ^= h;
    ctx.nblocks = ctx.nblocks.wrapping_add(1);
}

fn sm3_update_ctx(ctx: &mut super::bindings::sm3_ctx_t, mut data: &[u8]) {
    if ctx.num > 0 {
        let used = ctx.num as usize;
        let fill = (64 - used).min(data.len());
        ctx.block[used..used + fill].copy_from_slice(&data[..fill]);
        ctx.num += fill as u32;
        data = &data[fill..];

        if ctx.num == 64 {
            let block = ctx.block;
            sm3_compress(ctx, &block);
            ctx.num = 0;
        }
    }

    while data.len() >= 64 {
        let mut block = [0u8; 64];
        block.copy_from_slice(&data[..64]);
        sm3_compress(ctx, &block);
        data = &data[64..];
    }

    if !data.is_empty() {
        ctx.block[..data.len()].copy_from_slice(data);
        ctx.num = data.len() as u32;
    }
}

#[no_mangle]
pub unsafe extern "C" fn generate_key_pair(
    private_key: *mut c_char,
    private_key_len: *mut size_t,
    public_key: *mut c_char,
    public_key_len: *mut size_t,
    type_: asymmetric_cryptograph_t,
) -> c_int {
    if type_ != asymmetric_cryptograph_t_SM2
        || private_key_len.is_null()
        || public_key_len.is_null()
    {
        return 1;
    }

    let result = (|| -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
        let group = sm2_group()?;
        let ec_key = EcKey::generate(&group)?;
        let private = hex_lower(&ec_key.private_key().to_vec_padded(32)?);
        let mut ctx = BigNumContext::new()?;
        let public = hex_lower(&ec_key.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )?);
        Ok((private, public))
    })();

    match result {
        Ok((private, public)) => {
            let private_status = copy_output(
                &private,
                private_key as *mut u8,
                private_key_len as *mut size_t,
            );
            let public_status = copy_output(
                &public,
                public_key as *mut u8,
                public_key_len as *mut size_t,
            );
            if private_status == 0 && public_status == 0 {
                0
            } else {
                1
            }
        }
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn asymmetric_encrypt(
    input: *const c_uchar,
    input_len: size_t,
    public_key: *const c_char,
    public_key_len: size_t,
    output: *mut c_uchar,
    output_len: *mut size_t,
    type_: asymmetric_cryptograph_t,
) -> c_int {
    if type_ != asymmetric_cryptograph_t_SM2 {
        return 1;
    }

    let result = (|| -> Result<Vec<u8>, ErrorStack> {
        let input = bytes_from_ptr(input, input_len).ok_or_else(ErrorStack::get)?;
        let public_key = ascii_key(public_key, public_key_len)?;
        let pkey = pkey_from_public_ascii(&public_key)?;
        let mut ctx = PkeyCtx::new(&pkey)?;
        ctx.encrypt_init()?;
        let mut encrypted = Vec::new();
        ctx.encrypt_to_vec(input, &mut encrypted)?;
        Ok(encrypted)
    })();

    match result {
        Ok(encrypted) => copy_output(&encrypted, output, output_len),
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn asymmetric_decrypt(
    input: *const c_uchar,
    input_len: size_t,
    private_key: *const c_char,
    private_key_len: size_t,
    output: *mut c_uchar,
    output_len: *mut size_t,
    type_: asymmetric_cryptograph_t,
) -> c_int {
    if type_ != asymmetric_cryptograph_t_SM2 {
        return 1;
    }

    let result = (|| -> Result<Vec<u8>, ErrorStack> {
        let input = bytes_from_ptr(input, input_len).ok_or_else(ErrorStack::get)?;
        let private_key = ascii_key(private_key, private_key_len)?;
        let pkey = pkey_from_private_ascii(&private_key)?;
        let mut ctx = PkeyCtx::new(&pkey)?;
        ctx.decrypt_init()?;
        let mut decrypted = Vec::new();
        ctx.decrypt_to_vec(input, &mut decrypted)?;
        Ok(decrypted)
    })();

    match result {
        Ok(decrypted) => copy_output(&decrypted, output, output_len),
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn sign(
    msg: *const c_uchar,
    msg_len: size_t,
    id: *const c_char,
    id_len: size_t,
    _public_key: *const c_char,
    _public_key_len: size_t,
    private_key: *const c_char,
    private_key_len: size_t,
    signature: *mut c_uchar,
    signature_len: *mut size_t,
    type_: signature_algorithm_t,
) -> c_int {
    if type_ != signature_algorithm_t_SM2_SIGN {
        return 1;
    }

    let result = (|| -> Result<Vec<u8>, ErrorStack> {
        let msg = bytes_from_ptr(msg, msg_len).ok_or_else(ErrorStack::get)?;
        let private_key = ascii_key(private_key, private_key_len)?;
        let pkey = pkey_from_private_ascii(&private_key)?;
        let mut pctx = PkeyCtx::new(&pkey)?;
        if set_sm2_id(&mut pctx, id, id_len) != 1 {
            return Err(ErrorStack::get());
        }

        let mut mctx = openssl::md_ctx::MdCtx::new()?;
        EVP_MD_CTX_set_pkey_ctx(mctx.as_ptr(), pctx.as_ptr());
        let mut inner = ptr::null_mut();
        if ffi::EVP_DigestSignInit(
            mctx.as_ptr(),
            &mut inner,
            Md::sm3().as_ptr(),
            ptr::null_mut(),
            pkey.as_ptr(),
        ) != 1
        {
            return Err(ErrorStack::get());
        }

        let mut len = 0usize;
        if ffi::EVP_DigestSign(
            mctx.as_ptr(),
            ptr::null_mut(),
            &mut len,
            msg.as_ptr(),
            msg.len(),
        ) != 1
        {
            return Err(ErrorStack::get());
        }

        let mut signature = vec![0u8; len];
        if ffi::EVP_DigestSign(
            mctx.as_ptr(),
            signature.as_mut_ptr(),
            &mut len,
            msg.as_ptr(),
            msg.len(),
        ) != 1
        {
            return Err(ErrorStack::get());
        }
        signature.truncate(len);
        Ok(signature)
    })();

    match result {
        Ok(signature_data) => copy_output(&signature_data, signature, signature_len),
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn verify(
    msg: *const c_uchar,
    msg_len: size_t,
    id: *const c_char,
    id_len: size_t,
    signature: *const c_uchar,
    signature_len: size_t,
    public_key: *const c_char,
    public_key_len: size_t,
    type_: signature_algorithm_t,
) -> c_int {
    if type_ != signature_algorithm_t_SM2_SIGN {
        return 1;
    }

    let result = (|| -> Result<bool, ErrorStack> {
        let msg = bytes_from_ptr(msg, msg_len).ok_or_else(ErrorStack::get)?;
        let signature = bytes_from_ptr(signature, signature_len).ok_or_else(ErrorStack::get)?;
        let public_key = ascii_key(public_key, public_key_len)?;
        let pkey = pkey_from_public_ascii(&public_key)?;
        let mut pctx = PkeyCtx::new(&pkey)?;
        if set_sm2_id(&mut pctx, id, id_len) != 1 {
            return Err(ErrorStack::get());
        }

        let mut mctx = openssl::md_ctx::MdCtx::new()?;
        EVP_MD_CTX_set_pkey_ctx(mctx.as_ptr(), pctx.as_ptr());
        let mut inner = ptr::null_mut();
        if ffi::EVP_DigestVerifyInit(
            mctx.as_ptr(),
            &mut inner,
            Md::sm3().as_ptr(),
            ptr::null_mut(),
            pkey.as_ptr(),
        ) != 1
        {
            return Err(ErrorStack::get());
        }

        let status = ffi::EVP_DigestVerify(
            mctx.as_ptr(),
            signature.as_ptr(),
            signature.len(),
            msg.as_ptr(),
            msg.len(),
        );
        Ok(status == 1)
    })();

    match result {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(_) => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn gcm_encrypt(
    input: *const c_uchar,
    input_len: size_t,
    output: *mut c_uchar,
    output_len: *mut size_t,
    tag: *mut c_uchar,
    tag_len: *mut size_t,
    key: *const c_uchar,
    key_len: size_t,
    iv: *const c_uchar,
    iv_len: size_t,
    aad: *const c_uchar,
    aad_len: size_t,
    _padding: padding_t,
    type_: symmetric_cryptograph_t,
) -> c_int {
    if type_ != symmetric_cryptograph_t_SM4 || output_len.is_null() || tag_len.is_null() {
        return 1;
    }

    let result = (|| -> Option<c_int> {
        let input = bytes_from_ptr(input, input_len)?;
        let output = bytes_from_mut_ptr(output, *output_len)?;
        let tag = bytes_from_mut_ptr(tag, *tag_len)?;
        let key = bytes_from_ptr(key, key_len)?;
        let iv = bytes_from_ptr(iv, iv_len)?;
        let aad = bytes_from_ptr(aad, aad_len)?;
        Some(sm4_gcm_encrypt(input, output, tag, key, iv, aad))
    })();

    if result == Some(0) {
        *output_len = input_len;
        0
    } else {
        1
    }
}

#[no_mangle]
pub unsafe extern "C" fn gcm_decrypt(
    input: *const c_uchar,
    input_len: size_t,
    output: *mut c_uchar,
    output_len: *mut size_t,
    tag: *const c_uchar,
    tag_len: size_t,
    key: *const c_uchar,
    key_len: size_t,
    iv: *const c_uchar,
    iv_len: size_t,
    aad: *const c_uchar,
    aad_len: size_t,
    _padding: padding_t,
    type_: symmetric_cryptograph_t,
) -> c_int {
    if type_ != symmetric_cryptograph_t_SM4 || output_len.is_null() {
        return 1;
    }

    let result = (|| -> Option<c_int> {
        let input = bytes_from_ptr(input, input_len)?;
        let output = bytes_from_mut_ptr(output, *output_len)?;
        let tag = bytes_from_ptr(tag, tag_len)?;
        let key = bytes_from_ptr(key, key_len)?;
        let iv = bytes_from_ptr(iv, iv_len)?;
        let aad = bytes_from_ptr(aad, aad_len)?;
        Some(sm4_gcm_decrypt(input, output, tag, key, iv, aad))
    })();

    if result == Some(0) {
        *output_len = input_len;
        0
    } else {
        1
    }
}

#[no_mangle]
pub unsafe extern "C" fn SM3Init(ctx: *mut super::bindings::sm3_ctx_t) -> c_int {
    if ctx.is_null() {
        return 1;
    }

    (*ctx).digest = SM3_IV;
    (*ctx).nblocks = 0;
    (*ctx).block = [0; 64];
    (*ctx).num = 0;
    0
}

#[no_mangle]
pub unsafe extern "C" fn SM3Update(
    ctx: *mut super::bindings::sm3_ctx_t,
    data: *const c_uchar,
    data_len: size_t,
) -> c_int {
    if ctx.is_null() || (data.is_null() && data_len != 0) {
        return 1;
    }

    let data = slice::from_raw_parts(data, data_len as usize);
    sm3_update_ctx(&mut *ctx, data);
    0
}

#[no_mangle]
pub unsafe extern "C" fn SM3Final(
    ctx: *mut super::bindings::sm3_ctx_t,
    digest: *mut c_uchar,
) -> c_int {
    if ctx.is_null() || digest.is_null() {
        return 1;
    }

    let ctx = &mut *ctx;
    let total_bits = ((ctx.nblocks as u64) * 64 + (ctx.num as u64)) * 8;
    let used = ctx.num as usize;
    ctx.block[used] = 0x80;

    if used + 1 > 56 {
        ctx.block[used + 1..].fill(0);
        let block = ctx.block;
        sm3_compress(ctx, &block);
        ctx.block = [0; 64];
    } else {
        ctx.block[used + 1..56].fill(0);
    }

    ctx.block[56..64].copy_from_slice(&total_bits.to_be_bytes());
    let block = ctx.block;
    sm3_compress(ctx, &block);
    ctx.num = 0;

    for (index, value) in ctx.digest.iter().enumerate() {
        ptr::copy_nonoverlapping(value.to_be_bytes().as_ptr(), digest.add(index * 4), 4);
    }

    0
}
