use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::AegisError;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_PACKET_SIZE: usize = 50 * 1024 * 1024; // 50MB
const ARGON2ID_OUTPUT_LEN: usize = 32;
const ARGON2ID_M_COST_KIB: u32 = 65_536;
const ARGON2ID_T_COST: u32 = 4;
const ARGON2ID_P_COST: u32 = 2;

#[allow(clippy::missing_errors_doc)]
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

#[allow(clippy::missing_errors_doc)]
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

    if payload_len > MAX_PACKET_SIZE {
        return Err(AegisError::PacketTooLarge {
            size: payload_len,
            limit: MAX_PACKET_SIZE,
        });
    }

    if rest.len() != payload_len + TAG_LEN {
        return Err(AegisError::CryptoError {
            message: "密文长度与 PayloadLen 不匹配".to_string(),
            code: None,
        });
    }

    cipher
        .decrypt(nonce, rest)
        .map_err(|_| AegisError::CryptoError {
            message: "解密失败".to_string(),
            code: None,
        })
}

#[allow(clippy::missing_errors_doc)]
pub fn derive_kek_argon2id(
    password: &[u8],
    salt: &[u8],
) -> Result<[u8; ARGON2ID_OUTPUT_LEN], AegisError> {
    let params = Params::new(
        ARGON2ID_M_COST_KIB,
        ARGON2ID_T_COST,
        ARGON2ID_P_COST,
        Some(ARGON2ID_OUTPUT_LEN),
    )
    .map_err(|e| AegisError::CryptoError {
        message: format!("Argon2 参数错误: {e}"),
        code: None,
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; ARGON2ID_OUTPUT_LEN];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| AegisError::CryptoError {
            message: format!("Argon2id 派生失败: {e}"),
            code: None,
        })?;
    Ok(out)
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

    #[test]
    fn test_decrypt_packet_too_large() {
        let key = [1u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let payload_len_u32: u32 = 50 * 1024 * 1024 + 1;

        let mut packet = Vec::new();
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&payload_len_u32.to_be_bytes());
        packet.extend_from_slice(&[0u8; TAG_LEN]);

        let err = decrypt(packet.as_slice(), key.as_slice()).err();
        assert!(matches!(
            err,
            Some(AegisError::PacketTooLarge { size, limit })
                if size == MAX_PACKET_SIZE + 1 && limit == MAX_PACKET_SIZE
        ));
    }

    #[test]
    fn argon2id_derive_is_deterministic() -> Result<(), AegisError> {
        let password = b"test-password";
        let salt = [7u8; 32];
        let k1 = derive_kek_argon2id(password.as_slice(), salt.as_slice())?;
        let k2 = derive_kek_argon2id(password.as_slice(), salt.as_slice())?;
        assert_eq!(k1, k2);
        Ok(())
    }

    #[test]
    fn argon2id_derive_changes_with_password() -> Result<(), AegisError> {
        let salt = [9u8; 32];
        let k1 = derive_kek_argon2id(b"a".as_slice(), salt.as_slice())?;
        let k2 = derive_kek_argon2id(b"b".as_slice(), salt.as_slice())?;
        assert_ne!(k1, k2);
        Ok(())
    }
}
