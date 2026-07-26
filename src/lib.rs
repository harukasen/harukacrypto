use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U16;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use sha2::{Digest, Sha256};

type AesBlock = GenericArray<u8, U16>;

#[inline(always)]
fn block_from_slice(s: &[u8]) -> AesBlock {
    let mut b = [0u8; 16];
    b.copy_from_slice(&s[..16]);
    AesBlock::from(b)
}

#[inline(always)]
fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for (ai, &bi) in a.iter_mut().zip(b.iter()) {
        *ai ^= bi;
    }
}

#[inline(always)]
fn xor_blocks(a: &mut AesBlock, b: &AesBlock) {
    for (ai, &bi) in a.iter_mut().zip(b.iter()) {
        *ai ^= bi;
    }
}

fn ige256_encrypt_slice(data: &mut [u8], cipher: &Aes256, iv: &[u8]) {
    let mut iv1 = block_from_slice(&iv[..16]);
    let mut iv2 = block_from_slice(&iv[16..]);
    for chunk in data.chunks_exact_mut(16) {
        let plain = block_from_slice(chunk);
        let mut block = plain;
        xor_blocks(&mut block, &iv1);
        cipher.encrypt_block(&mut block);
        xor_blocks(&mut block, &iv2);
        chunk.copy_from_slice(&block);
        iv1 = block;
        iv2 = plain;
    }
}

fn ige256_decrypt_slice(data: &mut [u8], cipher: &Aes256, iv: &[u8]) {
    let mut iv1 = block_from_slice(&iv[16..]);
    let mut iv2 = block_from_slice(&iv[..16]);
    for chunk in data.chunks_exact_mut(16) {
        let cipher_block = block_from_slice(chunk);
        let mut block = iv1;
        xor_blocks(&mut block, &cipher_block);
        cipher.decrypt_block(&mut block);
        xor_blocks(&mut block, &iv2);
        chunk.copy_from_slice(&block);
        iv1 = block;
        iv2 = cipher_block;
    }
}

const KDF_A_LO: usize = 0;
const KDF_A_HI: usize = 36;
const KDF_B_LO: usize = 40;
const KDF_B_HI: usize = 76;
const MSG_KEY_AUTH_LO: usize = 88;
const MSG_KEY_AUTH_HI: usize = 120;

#[inline(always)]
fn kdf_inner(auth_key: &[u8], msg_key: &[u8], x: usize) -> ([u8; 32], [u8; 32]) {
    let sha_a = {
        let mut h = Sha256::new();
        h.update(msg_key);
        h.update(&auth_key[x + KDF_A_LO..x + KDF_A_HI]);
        h.finalize()
    };
    let sha_b = {
        let mut h = Sha256::new();
        h.update(&auth_key[x + KDF_B_LO..x + KDF_B_HI]);
        h.update(msg_key);
        h.finalize()
    };

    let mut aes_key = [0u8; 32];
    aes_key[..8].copy_from_slice(&sha_a[..8]);
    aes_key[8..24].copy_from_slice(&sha_b[8..24]);
    aes_key[24..32].copy_from_slice(&sha_a[24..32]);

    let mut aes_iv = [0u8; 32];
    aes_iv[..8].copy_from_slice(&sha_b[..8]);
    aes_iv[8..24].copy_from_slice(&sha_a[8..24]);
    aes_iv[24..32].copy_from_slice(&sha_b[24..32]);

    (aes_key, aes_iv)
}

#[inline(always)]
fn ctr_next(ctr: &mut [u8; 16]) {
    for k in (0..16).rev() {
        ctr[k] = ctr[k].wrapping_add(1);
        if ctr[k] != 0 { break; }
    }
}

fn ctr_process(data: &mut [u8], cipher: &Aes256, ctr: &mut [u8; 16], state: &mut usize) {
    let len = data.len();
    if len == 0 { return; }

    let mut pos = 0;

    if *state != 0 {
        let mut ks = block_from_slice(ctr);
        cipher.encrypt_block(&mut ks);
        let take = (16 - *state).min(len);
        for i in 0..take {
            data[pos + i] ^= ks[*state + i];
        }
        pos += take;
        *state += take;
        if *state == 16 {
            *state = 0;
            ctr_next(ctr);
        }
        if pos == len { return; }
    }

    let mut chunks4 = data[pos..].chunks_exact_mut(64);
    for quad in &mut chunks4 {
        let mut k0 = block_from_slice(ctr); ctr_next(ctr);
        let mut k1 = block_from_slice(ctr); ctr_next(ctr);
        let mut k2 = block_from_slice(ctr); ctr_next(ctr);
        let mut k3 = block_from_slice(ctr); ctr_next(ctr);
        cipher.encrypt_block(&mut k0);
        cipher.encrypt_block(&mut k1);
        cipher.encrypt_block(&mut k2);
        cipher.encrypt_block(&mut k3);
        xor_bytes(&mut quad[0..16], &k0);
        xor_bytes(&mut quad[16..32], &k1);
        xor_bytes(&mut quad[32..48], &k2);
        xor_bytes(&mut quad[48..64], &k3);
    }
    let remainder = chunks4.into_remainder();
    let mut chunks = remainder.chunks_exact_mut(16);
    for chunk in &mut chunks {
        let mut ks = block_from_slice(ctr);
        cipher.encrypt_block(&mut ks);
        xor_bytes(chunk, &ks);
        ctr_next(ctr);
    }
    let tail = chunks.into_remainder();

    if !tail.is_empty() {
        let mut ks = block_from_slice(ctr);
        cipher.encrypt_block(&mut ks);
        for i in 0..tail.len() {
            tail[i] ^= ks[i];
        }
        *state = tail.len();
    }
}

#[pyfunction]
fn ige256_encrypt(py: Python<'_>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    if iv.len() != 32 { return Err(PyValueError::new_err("IV must be 32 bytes")); }
    let data = data.to_vec();
    let key = key.to_vec();
    let iv = iv.to_vec();
    Ok(py.detach(move || {
        let cipher = Aes256::new_from_slice(&key).unwrap();
        let mut buf = data;
        ige256_encrypt_slice(&mut buf, &cipher, &iv);
        buf
    }))
}

#[pyfunction]
fn ige256_decrypt(py: Python<'_>, data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<Vec<u8>> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    if iv.len() != 32 { return Err(PyValueError::new_err("IV must be 32 bytes")); }
    let data = data.to_vec();
    let key = key.to_vec();
    let iv = iv.to_vec();
    Ok(py.detach(move || {
        let cipher = Aes256::new_from_slice(&key).unwrap();
        let mut buf = data;
        ige256_decrypt_slice(&mut buf, &cipher, &iv);
        buf
    }))
}

#[pyfunction]
fn ctr256_encrypt(
    py: Python<'_>,
    data: &[u8],
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<Vec<u8>> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    if iv.len() != 16 { return Err(PyValueError::new_err("IV must be 16 bytes")); }

    let data = data.to_vec();
    let key = key.to_vec();
    let mut ctr = [0u8; 16];
    unsafe {
        ctr.copy_from_slice(iv.as_bytes());
    }
    let mut state_off = unsafe { state.as_bytes()[0] } as usize;
    if state_off >= 16 { state_off = 0; }

    let (buf, ctr_out, state_out) = py.detach(move || {
        let cipher = Aes256::new_from_slice(&key).unwrap();
        let mut buf = data;
        ctr_process(&mut buf, &cipher, &mut ctr, &mut state_off);
        (buf, ctr, state_off)
    });

    unsafe {
        iv.as_bytes_mut().copy_from_slice(&ctr_out);
        state.as_bytes_mut()[0] = state_out as u8;
    }
    Ok(buf)
}

#[pyfunction]
fn ctr256_decrypt(
    py: Python<'_>,
    data: &[u8],
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<Vec<u8>> {
    ctr256_encrypt(py, data, key, iv, state)
}

/// In-place CTR encrypt: copies data out, processes, writes back.
/// Saves one allocation vs the returning version.
#[pyfunction]
fn ctr256_encrypt_inplace(
    py: Python<'_>,
    data: &Bound<'_, PyByteArray>,
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<()> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    if iv.len() != 16 { return Err(PyValueError::new_err("IV must be 16 bytes")); }

    let mut buf = unsafe { data.as_bytes() }.to_vec();
    let key_vec = key.to_vec();
    let mut ctr = [0u8; 16];
    unsafe { ctr.copy_from_slice(iv.as_bytes()); }
    let mut state_off = unsafe { state.as_bytes()[0] } as usize;
    if state_off >= 16 { state_off = 0; }

    let (buf, ctr_out, state_out) = py.detach(move || {
        let cipher = Aes256::new_from_slice(&key_vec).unwrap();
        ctr_process(&mut buf, &cipher, &mut ctr, &mut state_off);
        (buf, ctr, state_off)
    });

    unsafe {
        data.as_bytes_mut().copy_from_slice(&buf);
        iv.as_bytes_mut().copy_from_slice(&ctr_out);
        state.as_bytes_mut()[0] = state_out as u8;
    }
    Ok(())
}

#[pyfunction]
fn ctr256_decrypt_inplace(
    py: Python<'_>,
    data: &Bound<'_, PyByteArray>,
    key: &[u8],
    iv: &Bound<'_, PyByteArray>,
    state: &Bound<'_, PyByteArray>,
) -> PyResult<()> {
    ctr256_encrypt_inplace(py, data, key, iv, state)
}

/// Batch CTR encrypt: all data passed as a single flat buffer with sizes list.
/// Eliminates per-item Python list indexing (O(1) Python calls regardless of batch size).
#[pyfunction]
fn ctr256_encrypt_batch(
    _py: Python<'_>,
    data_flat: &[u8],
    sizes: &Bound<'_, PyByteArray>,
    key: &[u8],
    ivs: &Bound<'_, PyByteArray>,
    states: &Bound<'_, PyByteArray>,
) -> PyResult<Vec<u8>> {
    if key.len() != 32 { return Err(PyValueError::new_err("Key must be 32 bytes")); }
    let n = states.len();
    if n == 0 { return Ok(Vec::new()); }
    if ivs.len() != n * 16 { return Err(PyValueError::new_err("ivs must be 16*n bytes")); }
    if sizes.len() != n * 4 { return Err(PyValueError::new_err("sizes must be 4*n bytes")); }

    let mut offsets: Vec<usize> = Vec::with_capacity(n + 1);
    offsets.push(0);
    let mut total = 0usize;
    unsafe {
        let sz_bytes = sizes.as_bytes();
        for i in 0..n {
            let sz = u32::from_le_bytes([
                sz_bytes[i * 4],
                sz_bytes[i * 4 + 1],
                sz_bytes[i * 4 + 2],
                sz_bytes[i * 4 + 3],
            ]) as usize;
            total += sz;
            offsets.push(total);
        }
    }
    if total > data_flat.len() {
        return Err(PyValueError::new_err("data_flat too short for given sizes"));
    }

    let key_vec = key.to_vec();
    let mut data_owned = data_flat.to_vec();

    let mut ctrs: Vec<[u8; 16]> = Vec::with_capacity(n);
    let mut state_offs: Vec<usize> = Vec::with_capacity(n);
    unsafe {
        let iv_bytes = ivs.as_bytes();
        let st_bytes = states.as_bytes();
        for i in 0..n {
            let mut ctr = [0u8; 16];
            ctr.copy_from_slice(&iv_bytes[i * 16..][..16]);
            ctrs.push(ctr);
            state_offs.push(st_bytes[i] as usize);
        }
    }

    let results = _py.detach(move || {
        let cipher = Aes256::new_from_slice(&key_vec).unwrap();
        for i in 0..n {
            let slice = &mut data_owned[offsets[i]..offsets[i + 1]];
            ctr_process(slice, &cipher, &mut ctrs[i], &mut state_offs[i]);
        }
        (data_owned, ctrs, state_offs)
    });

    let (data_out, ctrs_out, state_offs_out) = results;
    unsafe {
        for i in 0..n {
            ivs.as_bytes_mut()[i * 16..][..16].copy_from_slice(&ctrs_out[i]);
            states.as_bytes_mut()[i] = state_offs_out[i] as u8;
        }
    }
    Ok(data_out)
}

#[pyfunction]
fn ctr256_decrypt_batch(
    py: Python<'_>,
    data_flat: &[u8],
    sizes: &Bound<'_, PyByteArray>,
    key: &[u8],
    ivs: &Bound<'_, PyByteArray>,
    states: &Bound<'_, PyByteArray>,
) -> PyResult<Vec<u8>> {
    ctr256_encrypt_batch(py, data_flat, sizes, key, ivs, states)
}

#[pyfunction]
fn kdf(auth_key: &[u8], msg_key: &[u8], outgoing: bool) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let x: usize = if outgoing { 0 } else { 8 };
    let (key_arr, iv_arr) = kdf_inner(auth_key, msg_key, x);
    Ok((key_arr.to_vec(), iv_arr.to_vec()))
}

#[pyfunction]
fn pack_message(py: Python<'_>, msg_id: i64, seq_no: i32, body: &[u8], salt: i64, session_id: &[u8], auth_key: &[u8], auth_key_id: &[u8]) -> PyResult<Vec<u8>> {
    let body = body.to_vec();
    let session_id = session_id.to_vec();
    let auth_key = auth_key.to_vec();
    let auth_key_id = auth_key_id.to_vec();

    Ok(py.detach(move || {
        let body_len = body.len();
        let inner_len = 8 + 8 + 8 + 4 + 4 + body_len;
        let total_plain = (inner_len + 12 + 15) & !15;
        let total_out = 24 + total_plain;
        let mut out = vec![0u8; total_out];
        let plain = &mut out[24..];

        let (salt_slice, rest) = plain.split_at_mut(8);
        salt_slice.copy_from_slice(&(salt as u64).to_le_bytes());
        let (sid, rest) = rest.split_at_mut(8);
        sid.copy_from_slice(&session_id);
        let (mid, rest) = rest.split_at_mut(8);
        mid.copy_from_slice(&(msg_id as u64).to_le_bytes());
        let (sn, rest) = rest.split_at_mut(4);
        sn.copy_from_slice(&(seq_no as u32).to_le_bytes());
        let (lenb, rest) = rest.split_at_mut(4);
        lenb.copy_from_slice(&(body_len as u32).to_le_bytes());
        let (data_slice, padding) = rest.split_at_mut(body_len);
        data_slice.copy_from_slice(&body);
        let _ = getrandom::getrandom(padding);

        // https://core.telegram.org/mtproto/description
        // msg_key = SHA256(auth_key[88+x:88+x+32] + plaintext)[8:24]
        // x=0 for outgoing (client→server), so auth_key[88:120]
        let msg_key_large = {
            let mut h = Sha256::new();
            h.update(&auth_key[MSG_KEY_AUTH_LO..MSG_KEY_AUTH_HI]);
            h.update(&plain[..total_plain]);
            h.finalize()
        };
        let msg_key = &msg_key_large[8..24];

        let (aes_key, aes_iv) = kdf_inner(&auth_key, msg_key, 0);
        let cipher = Aes256::new_from_slice(&aes_key).unwrap();
        ige256_encrypt_slice(&mut out[24..], &cipher, &aes_iv);

        out[..8].copy_from_slice(&auth_key_id);
        out[8..24].copy_from_slice(msg_key);
        out
    }))
}

#[pyfunction]
#[pyo3(signature = (packed, session_id, auth_key, auth_key_id, incoming=true))]
fn unpack_message(py: Python<'_>, packed: &[u8], session_id: &[u8], auth_key: &[u8], auth_key_id: &[u8], incoming: bool) -> PyResult<(i64, i32, i32, Vec<u8>, i32)> {
    if packed.len() < 24 {
        return Err(PyValueError::new_err("packed data too short"));
    }
    if &packed[..8] != auth_key_id {
        return Err(PyValueError::new_err("auth_key_id mismatch"));
    }
    let packed = packed.to_vec();
    let session_id = session_id.to_vec();
    let auth_key = auth_key.to_vec();
    let x: usize = if incoming { 8 } else { 0 };

    py.detach(move || {
        let msg_key = &packed[8..24];
        let encrypted = &packed[24..];

        let (aes_key, aes_iv) = kdf_inner(&auth_key, msg_key, x);
        let cipher = Aes256::new_from_slice(&aes_key).unwrap();
        let mut dec = encrypted.to_vec();
        ige256_decrypt_slice(&mut dec, &cipher, &aes_iv);

        if dec.len() < 16 {
            return Err(PyValueError::new_err("msg_key mismatch"));
        }

        // https://core.telegram.org/mtproto/description
        // msg_key = SHA256(auth_key[88+x:88+x+32] + plaintext + padding)[8:24]
        // where x=0 for client->server (outgoing), x=8 for server->client (incoming)
        // https://core.telegram.org/mtproto/security_guidelines#checking-sha256-hash-value-of-msg-key
        // Note: the security guidelines page incorrectly omits the x offset (always shows 88:120)
        let (msg_key_lo, msg_key_hi) = if incoming {
            (96usize, 128usize)
        } else {
            (88usize, 120usize)
        };
        let msg_key_check = {
            let mut h = Sha256::new();
            h.update(&auth_key[msg_key_lo..msg_key_hi]);
            h.update(&dec);
            h.finalize()
        };
        if &msg_key_check[8..24] != msg_key {
            return Err(PyValueError::new_err("msg_key mismatch"));
        }

        // https://core.telegram.org/mtproto/security_guidelines#checking-session-id
        if &dec[8..16] != &session_id[..] {
            return Err(PyValueError::new_err("session_id mismatch"));
        }
        let msg_id = i64::from_le_bytes(dec[16..24].try_into().unwrap());
        let seq_no = i32::from_le_bytes(dec[24..28].try_into().unwrap());
        let length = i32::from_le_bytes(dec[28..32].try_into().unwrap()) as usize;
        let body = dec[32..32 + length].to_vec();
        let total_len = dec[16..].len() as i32;
        Ok((msg_id, seq_no, length as i32, body, total_len))
    })
}

#[pymodule]
fn warpcrypto(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt_inplace, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_encrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_decrypt_batch, m)?)?;
    m.add_function(wrap_pyfunction!(kdf, m)?)?;
    m.add_function(wrap_pyfunction!(pack_message, m)?)?;
    m.add_function(wrap_pyfunction!(unpack_message, m)?)?;
    Ok(())
}
