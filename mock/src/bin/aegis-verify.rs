#![allow(missing_docs)]

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aes_kw::Kek;
use argon2::{Algorithm, Argon2, Params, Version};
use clap::Parser;
use common::crypto;
use common::error::{AegisError, ErrorCode};
use common::protocol::{AgentTelemetry, FileInfo, NetworkInterfaceUpdate, ProcessInfo, SystemInfo};
use prost::Message;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;

const HEADER_LEN: usize = 144;
const MAGIC: &[u8; 5] = b"AEGIS";
const VERSION: u8 = 0x01;
const CIPHER_ID_XCHACHA20: u8 = 0x01;
const KDF_SALT_OFFSET: usize = 0x08;
const KDF_SALT_LEN: usize = 32;
const HOST_UUID_OFFSET: usize = 0x28;
const HOST_UUID_LEN: usize = 16;
const USER_SLOT_LEN: usize = 40;
const MAX_CHUNK_PAYLOAD_LEN: usize = 50 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(name = "aegis-verify", version)]
struct Cli {
    input: PathBuf,

    #[arg(long = "password")]
    password: String,

    #[arg(long = "mode", default_value = "dev")]
    mode: String,

    #[arg(long = "cert")]
    cert: Option<PathBuf>,

    #[arg(long = "dump")]
    dump: bool,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AegisError> {
    let cli = Cli::parse();
    verify(
        cli.input.as_path(),
        cli.password.as_str(),
        cli.mode.as_str(),
        cli.cert.as_deref(),
        cli.dump,
    )
}

#[allow(clippy::too_many_lines)]
fn verify(
    input: &Path,
    password: &str,
    mode: &str,
    cert: Option<&Path>,
    dump: bool,
) -> Result<(), AegisError> {
    if mode != "dev" && mode != "prod" {
        return Err(AegisError::ConfigError {
            message: format!("不支持的 mode: {mode}，仅支持 dev/prod"),
        });
    }

    let artifact = fs::read(input).map_err(|err| io_error_with_path(&err, input))?;
    if artifact.len() < HEADER_LEN + USER_SLOT_LEN + 24 + 4 + 16 {
        return Err(AegisError::ProtocolError {
            message: "Artifact 长度不足".to_string(),
            code: None,
        });
    }

    validate_header(artifact.as_slice())?;
    let kdf_salt: [u8; KDF_SALT_LEN] = artifact[KDF_SALT_OFFSET..KDF_SALT_OFFSET + KDF_SALT_LEN]
        .try_into()
        .map_err(|_| AegisError::ProtocolError {
            message: "读取 KDF_Salt 失败".to_string(),
            code: None,
        })?;

    let host_uuid = &artifact[HOST_UUID_OFFSET..HOST_UUID_OFFSET + HOST_UUID_LEN];
    if !host_uuid.iter().any(|b| *b != 0) {
        return Err(AegisError::ProtocolError {
            message: "HostUUID 为全 0".to_string(),
            code: None,
        });
    }

    let public_key = load_rsa_public_key(resolve_public_key_der(mode, cert)?.as_slice())?;
    let rsa_ct_len = public_key.size();

    let user_slot_start = HEADER_LEN;
    let user_slot_end = user_slot_start + USER_SLOT_LEN;
    let user_slot =
        artifact
            .get(user_slot_start..user_slot_end)
            .ok_or(AegisError::ProtocolError {
                message: "读取 User Slot 失败".to_string(),
                code: None,
            })?;

    let rsa_start = user_slot_end;
    let rsa_end = rsa_start + rsa_ct_len;
    let _org_slot = artifact
        .get(rsa_start..rsa_end)
        .ok_or(AegisError::ProtocolError {
            message: "读取 Org Slot 失败".to_string(),
            code: None,
        })?;
    let stream = artifact.get(rsa_end..).ok_or(AegisError::ProtocolError {
        message: "读取 Data Body 失败".to_string(),
        code: None,
    })?;

    let session_key = unwrap_user_slot_session_key(password, &kdf_salt, user_slot)?;
    let plaintexts = decrypt_stream_to_plaintexts(stream, &session_key)?;

    if plaintexts.is_empty() {
        return Err(AegisError::ProtocolError {
            message: "解密后无任何 Chunk".to_string(),
            code: None,
        });
    }

    let system_info =
        SystemInfo::decode(plaintexts[0].as_slice()).map_err(|e| AegisError::ProtocolError {
            message: format!("第 1 个 Chunk 不是 SystemInfo: {e}"),
            code: None,
        })?;
    if system_info.hostname.trim().is_empty() {
        return Err(AegisError::ProtocolError {
            message: "SystemInfo.hostname 为空".to_string(),
            code: None,
        });
    }

    let mut last_net_ts: Option<i64> = None;

    if dump {
        println!(
            "Chunk#1 SystemInfo hostname={:?} os_version={:?} kernel_version={:?} ip_addresses={:?} boot_time={}",
            system_info.hostname,
            system_info.os_version,
            system_info.kernel_version,
            system_info.ip_addresses,
            system_info.boot_time
        );
    }

    for plaintext in plaintexts.iter().skip(1) {
        if let Ok(process) = ProcessInfo::decode(plaintext.as_slice()) {
            if process.exec_id == 0 {
                return Err(AegisError::ProtocolError {
                    message: "ProcessInfo.exec_id 为 0".to_string(),
                    code: None,
                });
            }
            if dump {
                println!(
                    "Chunk ProcessInfo exec_id={} pid={} ppid={} name={:?} cmdline={:?} exe_path={:?} uid={} start_time={} is_ghost={} is_mismatched={} has_floating_code={}",
                    process.exec_id,
                    process.pid,
                    process.ppid,
                    process.name,
                    process.cmdline,
                    process.exe_path,
                    process.uid,
                    process.start_time,
                    process.is_ghost,
                    process.is_mismatched,
                    process.has_floating_code
                );
            }
            continue;
        }

        if let Ok(telemetry) = AgentTelemetry::decode(plaintext.as_slice()) {
            if telemetry.dropped_events_count > 0 {
                println!("WARN: Trace file contains data loss events");
            }
            if dump {
                println!(
                    "Chunk AgentTelemetry timestamp={} cpu_usage_percent={} memory_usage_mb={} dropped_events_count={}",
                    telemetry.timestamp,
                    telemetry.cpu_usage_percent,
                    telemetry.memory_usage_mb,
                    telemetry.dropped_events_count
                );
            }
            continue;
        }

        if let Ok(net) = NetworkInterfaceUpdate::decode(plaintext.as_slice()) {
            if let Some(prev) = last_net_ts
                && net.timestamp <= prev
            {
                return Err(AegisError::ProtocolError {
                    message: "NetworkInterfaceUpdate 时间戳非单调递增".to_string(),
                    code: None,
                });
            }
            last_net_ts = Some(net.timestamp);
            if dump {
                println!(
                    "Chunk NetworkInterfaceUpdate timestamp={} new_ip_addresses={:?}",
                    net.timestamp, net.new_ip_addresses
                );
            }
            continue;
        }

        match FileInfo::decode(plaintext.as_slice()) {
            Ok(file) => {
                if dump {
                    println!(
                        "Chunk FileInfo path={:?} size={} created_si={} created_fn={} modified={} is_timestomped={} is_locked={}",
                        file.path,
                        file.size,
                        file.created_si,
                        file.created_fn,
                        file.modified,
                        file.is_timestomped,
                        file.is_locked
                    );
                }
            }
            Err(_) => {
                if dump {
                    println!(
                        "Chunk Unknown len={} bytes_prefix={}",
                        plaintext.len(),
                        hex_prefix(plaintext.as_slice(), 16)
                    );
                }
            }
        }
    }

    Ok(())
}

fn hex_prefix(bytes: &[u8], max_len: usize) -> String {
    let take = bytes.len().min(max_len);
    let mut out = String::new();
    for (i, b) in bytes.iter().take(take).enumerate() {
        if i != 0 {
            out.push(' ');
        }
        if write!(&mut out, "{b:02x}").is_err() {
            break;
        }
    }
    out
}

fn validate_header(artifact: &[u8]) -> Result<(), AegisError> {
    if &artifact[0..MAGIC.len()] != MAGIC.as_slice() {
        return Err(AegisError::ProtocolError {
            message: "Magic 不匹配".to_string(),
            code: None,
        });
    }
    if artifact[0x05] != VERSION {
        return Err(AegisError::ProtocolError {
            message: "Version 不匹配".to_string(),
            code: None,
        });
    }
    if artifact[0x06] != CIPHER_ID_XCHACHA20 {
        return Err(AegisError::ProtocolError {
            message: "CipherID 不匹配".to_string(),
            code: None,
        });
    }
    Ok(())
}

fn unwrap_user_slot_session_key(
    password: &str,
    kdf_salt: &[u8; KDF_SALT_LEN],
    user_slot: &[u8],
) -> Result<[u8; 32], AegisError> {
    let kek_bytes = derive_kek(password.as_bytes(), kdf_salt.as_ref())?;
    let kek = Kek::from(kek_bytes);
    let unwrapped = kek
        .unwrap_vec(user_slot)
        .map_err(|e| AegisError::CryptoError {
            message: format!("AES-256-KeyWrap 解密 SessionKey 失败: {e}"),
            code: Some(ErrorCode::Crypto003),
        })?;
    unwrapped
        .as_slice()
        .try_into()
        .map_err(|_| AegisError::CryptoError {
            message: "SessionKey 长度不是 32 bytes".to_string(),
            code: Some(ErrorCode::Crypto003),
        })
}

fn derive_kek(password: &[u8], salt: &[u8]) -> Result<[u8; 32], AegisError> {
    let params = Params::new(65_536, 4, 2, Some(32)).map_err(|e| AegisError::ConfigError {
        message: format!("Argon2 参数错误: {e}"),
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| AegisError::CryptoError {
            message: format!("Argon2id 派生 KEK 失败: {e}"),
            code: Some(ErrorCode::Crypto003),
        })?;
    Ok(out)
}

fn decrypt_stream_to_plaintexts(
    stream: &[u8],
    session_key: &[u8; 32],
) -> Result<Vec<Vec<u8>>, AegisError> {
    let mut offset = 0usize;
    let mut plaintexts = Vec::new();

    while offset < stream.len() {
        if stream.len().saturating_sub(offset) < 24 + 4 + 16 {
            return Err(AegisError::ProtocolError {
                message: "Artifact chunk 长度不足".to_string(),
                code: None,
            });
        }

        let payload_len =
            u32::from_be_bytes(stream[offset + 24..offset + 28].try_into().map_err(|_| {
                AegisError::ProtocolError {
                    message: "读取 payload_len 失败".to_string(),
                    code: None,
                }
            })?) as usize;
        if payload_len > MAX_CHUNK_PAYLOAD_LEN {
            return Err(AegisError::PacketTooLarge {
                size: payload_len,
                limit: MAX_CHUNK_PAYLOAD_LEN,
            });
        }

        let chunk_len = (24usize)
            .checked_add(4)
            .and_then(|v| v.checked_add(payload_len))
            .and_then(|v| v.checked_add(16))
            .ok_or(AegisError::ProtocolError {
                message: "Artifact chunk_len 溢出".to_string(),
                code: None,
            })?;
        let next_offset = offset
            .checked_add(chunk_len)
            .ok_or(AegisError::ProtocolError {
                message: "Artifact offset 溢出".to_string(),
                code: None,
            })?;
        let chunk = stream
            .get(offset..next_offset)
            .ok_or(AegisError::ProtocolError {
                message: "Artifact chunk 截断".to_string(),
                code: None,
            })?;
        offset = next_offset;

        let plaintext = crypto::decrypt(chunk, session_key.as_slice())?;
        plaintexts.push(plaintext);
    }

    Ok(plaintexts)
}

fn resolve_public_key_der(mode: &str, cert: Option<&Path>) -> Result<Vec<u8>, AegisError> {
    match mode {
        "dev" => {
            if let Some(cert) = cert {
                return fs::read(cert).map_err(|err| io_error_with_path(&err, cert));
            }
            let workspace_root = find_workspace_root(&std::env::current_dir().map_err(io_error)?)
                .ok_or(AegisError::ConfigError {
                message: "无法定位 workspace root".to_string(),
            })?;
            let public_key_path = workspace_root.join("tests/keys/dev_org_public.der");
            fs::read(public_key_path.as_path())
                .map_err(|err| io_error_with_path(&err, public_key_path.as_path()))
        }
        "prod" => {
            let cert = cert.ok_or(AegisError::ConfigError {
                message: "prod 模式必须提供 --cert".to_string(),
            })?;
            fs::read(cert).map_err(|err| io_error_with_path(&err, cert))
        }
        _ => Err(AegisError::ConfigError {
            message: format!("不支持的 mode: {mode}"),
        }),
    }
}

fn load_rsa_public_key(der_bytes: &[u8]) -> Result<RsaPublicKey, AegisError> {
    RsaPublicKey::from_public_key_der(der_bytes)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(der_bytes))
        .map_err(|e| AegisError::ConfigError {
            message: format!("解析 Org Public Key DER 失败: {e}"),
        })
}

fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(dir) = current {
        let candidate = dir.join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(candidate.as_path())
            && text.contains("[workspace]")
        {
            return Some(dir.to_path_buf());
        }
        current = dir.parent();
    }
    None
}

fn io_error(err: io::Error) -> AegisError {
    AegisError::IoError(err)
}

fn io_error_with_path(err: &io::Error, path: &Path) -> AegisError {
    AegisError::IoError(io::Error::new(
        err.kind(),
        format!("{}: {}", path.display(), err),
    ))
}
