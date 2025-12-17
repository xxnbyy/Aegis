use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::AegisError;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, AegisError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AegisError::CryptoError {
        message: "无效的密钥长度，XChaCha20Poly1305 需要 32 字节密钥".to_string(),
        code: None,
    })?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext_and_tag =
        cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| AegisError::CryptoError {
                message: "加密失败".to_string(),
                code: None,
            })?;

    let payload_len = ciphertext_and_tag
        .len()
        .checked_sub(TAG_LEN)
        .ok_or_else(|| AegisError::CryptoError {
            message: "加密输出长度异常".to_string(),
            code: None,
        })?;

    let payload_len_u32: u32 = payload_len
        .try_into()
        .map_err(|_| AegisError::CryptoError {
            message: "密文过大，无法编码为 u32".to_string(),
            code: None,
        })?;

    let (ciphertext, tag) = ciphertext_and_tag.split_at(payload_len);

    let mut out = Vec::with_capacity(NONCE_LEN + 4 + ciphertext.len() + tag.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&payload_len_u32.to_be_bytes());
    out.extend_from_slice(ciphertext);
    out.extend_from_slice(tag);
    Ok(out)
}

pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, AegisError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AegisError::CryptoError {
        message: "无效的密钥长度，XChaCha20Poly1305 需要 32 字节密钥".to_string(),
        code: None,
    })?;

    if data.len() < NONCE_LEN + 4 + TAG_LEN {
        return Err(AegisError::CryptoError {
            message: "密文长度不足".to_string(),
            code: None,
        });
    }

    let (nonce_part, rest) = data.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_part);

    let (len_part, rest) = rest.split_at(4);
    let payload_len =
        u32::from_be_bytes([len_part[0], len_part[1], len_part[2], len_part[3]]) as usize;

    if rest.len() != payload_len + TAG_LEN {
        return Err(AegisError::CryptoError {
            message: "密文长度与 PayloadLen 不匹配".to_string(),
            code: None,
        });
    }

    let mut ciphertext_and_tag = Vec::with_capacity(payload_len + TAG_LEN);
    ciphertext_and_tag.extend_from_slice(rest);

    cipher
        .decrypt(nonce, ciphertext_and_tag.as_slice())
        .map_err(|_| AegisError::CryptoError {
            message: "解密失败".to_string(),
            code: None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrip_small() -> Result<(), AegisError> {
        let key = [7u8; 32];
        let plaintext = b"hello-aegis";
        let encrypted = encrypt(plaintext.as_slice(), key.as_slice())?;
        let decrypted = decrypt(encrypted.as_slice(), key.as_slice())?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip_large() -> Result<(), AegisError> {
        let key = [9u8; 32];
        let plaintext: Vec<u8> = (0u32..8192u32).map(|i| (i % 251) as u8).collect();
        let encrypted = encrypt(plaintext.as_slice(), key.as_slice())?;
        let decrypted = decrypt(encrypted.as_slice(), key.as_slice())?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }
}
