//! AES-GCM-SIV envelope for cert private keys at rest. Nonce is prefixed to
//! the ciphertext; key comes from `RELAY_DATA_KEY` (32 bytes). SIV is nonce-
//! misuse-resistant — relevant because we do not rotate keys.

use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use base64::Engine as _;
use rand::RngCore;

const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum EncError {
    #[error("key must decode to 32 bytes")]
    BadKey,
    #[error("ciphertext too short")]
    TooShort,
    #[error("decrypt failed")]
    Decrypt,
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

/// Encrypt `plaintext` with the 32-byte key and return a base64 string
/// (`nonce || ciphertext`).
pub fn encrypt_key(data_key: &[u8; 32], plaintext: &[u8]) -> String {
    let cipher = Aes256GcmSiv::new_from_slice(data_key).expect("32 bytes");
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), plaintext).expect("encrypt");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    base64::engine::general_purpose::STANDARD.encode(out)
}

pub fn decrypt_key(data_key: &[u8; 32], b64: &str) -> Result<Vec<u8>, EncError> {
    let raw = base64::engine::general_purpose::STANDARD.decode(b64)?;
    if raw.len() < NONCE_LEN + 16 {
        return Err(EncError::TooShort);
    }
    let (nonce, ct) = raw.split_at(NONCE_LEN);
    let cipher = Aes256GcmSiv::new_from_slice(data_key).map_err(|_| EncError::BadKey)?;
    cipher.decrypt(Nonce::from_slice(nonce), ct).map_err(|_| EncError::Decrypt)
}

/// Turn a base64-encoded data-key env var into the 32-byte array needed by
/// [`encrypt_key`] / [`decrypt_key`].
pub fn decode_data_key(b64: &str) -> Result<[u8; 32], EncError> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64)?;
    if bytes.len() < 32 {
        return Err(EncError::BadKey);
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes[..32]);
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [7u8; 32];
        let pt = b"a secret key";
        let ct = encrypt_key(&key, pt);
        let back = decrypt_key(&key, &ct).unwrap();
        assert_eq!(back, pt);
    }
}
