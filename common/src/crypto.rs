use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::Mac;

use crate::error::{AegisError, ErrorCode};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const MAX_PACKET_SIZE: usize = 50 * 1024 * 1024; // 50MB
const ARGON2ID_OUTPUT_LEN: usize = 32;
const ARGON2ID_M_COST_KIB: u32 = 65_536;
const ARGON2ID_T_COST: u32 = 4;
const ARGON2ID_P_COST: u32 = 2;

pub const HMAC_SIG_TRAILER_LEN: usize = 40;
pub const HMAC_SIG_MAGIC: [u8; 4] = *b"AEHS";
const HMAC_SIG_VERSION_V1: u8 = 1;
const HMAC_SIG_ALG_HMAC_SHA256: u8 = 1;
const HMAC_SIG_LABEL_V1: &[u8] = b"AEGIS-HMAC-SIG-v1";
type HmacSha256 = hmac::Hmac<sha2::Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacSigVerification {
    Missing,
    Valid,
    Invalid,
}

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
        return Err(AegisError::CryptoError {
            message: format!("PayloadLen 超过 50MB 上限: {payload_len}"),
            code: Some(ErrorCode::Crypto003),
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

#[allow(clippy::missing_errors_doc)]
pub fn append_hmac_sig_trailer_v1(
    bytes: &mut Vec<u8>,
    session_key: &[u8; 32],
) -> Result<(), AegisError> {
    let tag = compute_hmac_sig_v1(session_key, bytes.as_slice())?;
    bytes.extend_from_slice(HMAC_SIG_MAGIC.as_slice());
    bytes.push(HMAC_SIG_VERSION_V1);
    bytes.push(HMAC_SIG_ALG_HMAC_SHA256);
    bytes.extend_from_slice(&[0u8; 2]);
    bytes.extend_from_slice(tag.as_slice());
    Ok(())
}

#[allow(clippy::missing_errors_doc)]
pub fn verify_hmac_sig_trailer_v1(
    bytes: &[u8],
    session_key: &[u8; 32],
) -> Result<HmacSigVerification, AegisError> {
    let Some((trailer_start, tag)) = extract_hmac_sig_trailer_v1(bytes) else {
        return Ok(HmacSigVerification::Missing);
    };

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(session_key).map_err(|_| AegisError::CryptoError {
            message: "初始化 HMAC 失败".to_string(),
            code: None,
        })?;
    mac.update(HMAC_SIG_LABEL_V1);
    mac.update(
        bytes
            .get(..trailer_start)
            .ok_or(AegisError::ProtocolError {
                message: "HMAC trailer_start 越界".to_string(),
                code: None,
            })?,
    );
    Ok(match mac.verify_slice(tag.as_slice()) {
        Ok(()) => HmacSigVerification::Valid,
        Err(_) => HmacSigVerification::Invalid,
    })
}

fn compute_hmac_sig_v1(session_key: &[u8; 32], payload: &[u8]) -> Result<[u8; 32], AegisError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(session_key).map_err(|_| AegisError::CryptoError {
            message: "初始化 HMAC 失败".to_string(),
            code: None,
        })?;
    mac.update(HMAC_SIG_LABEL_V1);
    mac.update(payload);
    let out = mac.finalize().into_bytes();
    let arr: [u8; 32] = out
        .as_slice()
        .try_into()
        .map_err(|_| AegisError::CryptoError {
            message: "HMAC 输出长度异常".to_string(),
            code: None,
        })?;
    Ok(arr)
}

fn extract_hmac_sig_trailer_v1(bytes: &[u8]) -> Option<(usize, [u8; 32])> {
    let trailer_start = bytes.len().checked_sub(HMAC_SIG_TRAILER_LEN)?;
    let trailer = bytes.get(trailer_start..)?;
    let magic = trailer.get(0..4)?;
    if magic != HMAC_SIG_MAGIC.as_slice() {
        return None;
    }
    let version = *trailer.get(4)?;
    let alg = *trailer.get(5)?;
    if version != HMAC_SIG_VERSION_V1 || alg != HMAC_SIG_ALG_HMAC_SHA256 {
        return None;
    }
    if trailer.get(6..8)? != [0u8; 2].as_slice() {
        return None;
    }
    let tag: [u8; 32] = trailer.get(8..40)?.try_into().ok()?;
    Some((trailer_start, tag))
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
            Some(AegisError::CryptoError {
                code: Some(ErrorCode::Crypto003),
                ..
            })
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

    #[test]
    fn hmac_sig_roundtrip_and_verification() -> Result<(), AegisError> {
        let key = [3u8; 32];
        let mut bytes = b"hello".to_vec();
        assert_eq!(
            verify_hmac_sig_trailer_v1(bytes.as_slice(), &key)?,
            HmacSigVerification::Missing
        );
        append_hmac_sig_trailer_v1(&mut bytes, &key)?;
        assert_eq!(
            verify_hmac_sig_trailer_v1(bytes.as_slice(), &key)?,
            HmacSigVerification::Valid
        );
        bytes[0] ^= 0x01;
        assert_eq!(
            verify_hmac_sig_trailer_v1(bytes.as_slice(), &key)?,
            HmacSigVerification::Invalid
        );
        Ok(())
    }
}
