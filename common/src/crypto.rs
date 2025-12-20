use std::io;
#[cfg(not(windows))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::Mac;
use uuid::Uuid;
use xxhash_rust::xxh64::xxh64;

use crate::error::{AegisError, ErrorCode};

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
pub const AES_MAX_PAYLOAD_LEN: usize = 50 * 1024 * 1024;
const ARGON2ID_OUTPUT_LEN: usize = 32;
const ARGON2ID_M_COST_KIB: u32 = 65_536;
const ARGON2ID_T_COST: u32 = 4;
const ARGON2ID_P_COST: u32 = 2;

pub const HMAC_SIG_TRAILER_LEN: usize = 40;
pub const HMAC_SIG_MAGIC: [u8; 4] = *b"AEHS";
pub const HMAC_SIG_VERSION_V1: u8 = 1;
pub const HMAC_SIG_ALG_HMAC_SHA256: u8 = 1;
pub const HMAC_SIG_LABEL_V1: &[u8] = b"AEGIS-HMAC-SIG-v1";
type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub const AES_HEADER_LEN: usize = 144;
pub const AES_MAGIC: [u8; 5] = *b"AEGIS";
pub const AES_VERSION_V1: u8 = 0x01;
pub const AES_CIPHER_ID_XCHACHA20_POLY1305: u8 = 0x01;
pub const AES_COMP_ID_NONE: u8 = 0x00;
pub const AES_KDF_SALT_LEN: usize = 32;
pub const AES_KDF_SALT_OFFSET: usize = 0x08;
pub const AES_HOST_UUID_OFFSET: usize = 0x28;
pub const AES_HOST_UUID_LEN: usize = 16;
pub const AES_ORG_KEY_FP_OFFSET: usize = 0x38;

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

    if payload_len > AES_MAX_PAYLOAD_LEN {
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

pub fn org_pubkey_fingerprint_xxh64(org_pubkey_der: &[u8]) -> u64 {
    xxh64(org_pubkey_der, 0)
}

#[allow(clippy::missing_errors_doc)]
pub fn build_aes_header_v1(
    kdf_salt: &[u8; AES_KDF_SALT_LEN],
    host_uuid: &[u8; AES_HOST_UUID_LEN],
    org_key_fp: u64,
) -> [u8; AES_HEADER_LEN] {
    let mut header = [0u8; AES_HEADER_LEN];
    header[0..AES_MAGIC.len()].copy_from_slice(AES_MAGIC.as_slice());
    header[0x05] = AES_VERSION_V1;
    header[0x06] = AES_CIPHER_ID_XCHACHA20_POLY1305;
    header[0x07] = AES_COMP_ID_NONE;
    header[AES_KDF_SALT_OFFSET..AES_KDF_SALT_OFFSET + AES_KDF_SALT_LEN]
        .copy_from_slice(kdf_salt.as_slice());
    header[AES_HOST_UUID_OFFSET..AES_HOST_UUID_OFFSET + AES_HOST_UUID_LEN]
        .copy_from_slice(host_uuid.as_slice());
    header[AES_ORG_KEY_FP_OFFSET..AES_ORG_KEY_FP_OFFSET + 8]
        .copy_from_slice(org_key_fp.to_be_bytes().as_slice());
    header
}

#[allow(clippy::missing_errors_doc)]
pub fn get_or_create_host_uuid(mode: &str) -> Result<[u8; 16], AegisError> {
    let uuid = get_persisted_host_uuid(mode)?;
    if let Some(uuid) = uuid {
        return Ok(uuid);
    }

    let new_uuid = *Uuid::new_v4().as_bytes();
    persist_host_uuid(mode, &new_uuid)?;
    Ok(new_uuid)
}

fn get_persisted_host_uuid(mode: &str) -> Result<Option<[u8; 16]>, AegisError> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        if let Some(v) = try_read_host_uuid_registry(HKEY_LOCAL_MACHINE)? {
            return Ok(Some(v));
        }
        if let Some(v) = try_read_host_uuid_registry(HKEY_CURRENT_USER)? {
            return Ok(Some(v));
        }
        let _ = mode;
        Ok(None)
    }

    #[cfg(not(windows))]
    {
        let primary = Path::new("/etc/aegis/uuid");
        if let Some(v) = try_read_host_uuid_file(primary)? {
            return Ok(Some(v));
        }
        let fallback = user_uuid_path();
        if let Some(v) = try_read_host_uuid_file(fallback.as_path())? {
            return Ok(Some(v));
        }
        let _ = mode;
        Ok(None)
    }
}

fn persist_host_uuid(mode: &str, uuid: &[u8; 16]) -> Result<(), AegisError> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        if try_write_host_uuid_registry(HKEY_LOCAL_MACHINE, uuid).is_ok() {
            return Ok(());
        }
        if try_write_host_uuid_registry(HKEY_CURRENT_USER, uuid).is_ok() {
            if mode != "dev" {
                tracing::warn!(
                    "HostUUID 写入 HKLM\\SOFTWARE\\Aegis 失败，已降级写入 HKCU\\SOFTWARE\\Aegis"
                );
            }
            return Ok(());
        }
        Err(AegisError::ConfigError {
            message: "无法写入 HostUUID 至 HKLM/HKCU\\SOFTWARE\\Aegis（请以管理员权限运行）"
                .to_string(),
        })
    }

    #[cfg(not(windows))]
    {
        let primary = Path::new("/etc/aegis/uuid");
        if try_write_host_uuid_file(primary, uuid).is_ok() {
            return Ok(());
        }
        let fallback = user_uuid_path();
        if mode != "dev" {
            tracing::warn!(
                "HostUUID 写入 /etc/aegis/uuid 失败，已降级写入 {}",
                fallback.display()
            );
        }
        try_write_host_uuid_file(fallback.as_path(), uuid)?;
        Ok(())
    }
}

#[cfg(windows)]
fn try_read_host_uuid_registry(hive: winreg::HKEY) -> Result<Option<[u8; 16]>, AegisError> {
    use winreg::RegKey;

    let root = RegKey::predef(hive);
    let key = match root.open_subkey("SOFTWARE\\Aegis") {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AegisError::IoError(e)),
    };

    let uuid_str: String = match key.get_value("HostUUID") {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AegisError::IoError(e)),
    };

    match Uuid::parse_str(uuid_str.trim()) {
        Ok(u) => Ok(Some(*u.as_bytes())),
        Err(_) => Ok(None),
    }
}

#[cfg(windows)]
fn try_write_host_uuid_registry(hive: winreg::HKEY, uuid: &[u8; 16]) -> io::Result<()> {
    use winreg::RegKey;

    let root = RegKey::predef(hive);
    let (key, _) = root.create_subkey("SOFTWARE\\Aegis")?;
    let uuid_str = Uuid::from_bytes(*uuid).to_string();
    key.set_value("HostUUID", &uuid_str)
}

#[cfg(not(windows))]
fn user_uuid_path() -> PathBuf {
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join(".config").join("aegis").join("uuid")
}

#[cfg(not(windows))]
fn try_read_host_uuid_file(path: &Path) -> Result<Option<[u8; 16]>, AegisError> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AegisError::IoError(e)),
    };
    let Ok(arr) = bytes.as_slice().try_into() else {
        return Ok(None);
    };
    Ok(Some(arr))
}

#[cfg(not(windows))]
fn try_write_host_uuid_file(path: &Path, uuid: &[u8; 16]) -> Result<(), AegisError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(AegisError::IoError)?;
    }
    fs::write(path, uuid).map_err(AegisError::IoError)?;
    Ok(())
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
        let payload_len_u32: u32 =
            u32::try_from(AES_MAX_PAYLOAD_LEN.saturating_add(1)).unwrap_or(u32::MAX);

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
