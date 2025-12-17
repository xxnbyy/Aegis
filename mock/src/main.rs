#![allow(missing_docs)]

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use common::crypto;
use common::error::{AegisError, ErrorCode};
use common::protocol::{AgentTelemetry, NetworkInterfaceUpdate, ProcessInfo, SystemInfo};
use prost::Message;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha256;
use uuid::Uuid;
use xxhash_rust::xxh64::xxh64;

const HEADER_LEN: usize = 144;
const MAGIC: &[u8; 5] = b"AEGIS";
const VERSION: u8 = 0x01;
const CIPHER_ID_XCHACHA20: u8 = 0x01;
const KDF_SALT_OFFSET: usize = 0x08;
const KDF_SALT_LEN: usize = 32;
const HOST_UUID_OFFSET: usize = 0x28;
const HOST_UUID_LEN: usize = 16;
const ORG_KEY_FP_OFFSET: usize = 0x38;

#[derive(Parser, Debug)]
#[command(name = "mock", version)]
struct Cli {
    #[arg(long = "scenario")]
    scenario: PathBuf,

    #[arg(long = "out")]
    out: PathBuf,

    #[arg(long = "mode", default_value = "dev")]
    mode: String,
}

#[derive(Debug, serde::Deserialize)]
struct Scenario {
    events: Vec<EventSpec>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
enum EventSpec {
    #[serde(rename = "process")]
    Process {
        exec_id: u64,
        pid: Option<u32>,
        ppid: Option<u32>,
        name: Option<String>,
        cmdline: Option<String>,
        exe_path: Option<String>,
        uid: Option<u32>,
        start_time: Option<i64>,
        is_ghost: Option<bool>,
        is_mismatched: Option<bool>,
        has_floating_code: Option<bool>,
    },

    #[serde(rename = "telemetry")]
    Telemetry {
        dropped_events: u64,
        timestamp: Option<i64>,
        cpu_usage_percent: Option<u32>,
        memory_usage_mb: Option<u32>,
    },

    #[serde(rename = "network_change")]
    NetworkChange {
        timestamp: Option<i64>,
        new_ip_addresses: Vec<String>,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AegisError> {
    let cli = Cli::parse();
    run_with_paths(&cli.scenario, &cli.out, cli.mode.as_str())
}

fn run_with_paths(scenario_path: &Path, out_path: &Path, mode: &str) -> Result<(), AegisError> {
    if mode != "dev" {
        return Err(AegisError::ConfigError {
            message: format!("不支持的 mode: {mode}，当前仅支持 dev"),
        });
    }

    let workspace_root = find_workspace_root(&std::env::current_dir().map_err(io_error)?).ok_or(
        AegisError::ConfigError {
            message: "无法定位 workspace root（未找到包含 [workspace] 的 Cargo.toml）".to_string(),
        },
    )?;

    let public_key_path = workspace_root.join("tests/keys/dev_org_public.der");
    let public_key_der =
        fs::read(&public_key_path).map_err(|err| io_error_with_path(&err, &public_key_path))?;
    let public_key = load_rsa_public_key(&public_key_der)?;

    let scenario_bytes =
        fs::read(scenario_path).map_err(|err| io_error_with_path(&err, scenario_path))?;
    let scenario: Scenario =
        serde_yaml::from_slice(&scenario_bytes).map_err(|e| AegisError::ProtocolError {
            message: format!("Scenario YAML 解析失败: {e}"),
            code: Some(ErrorCode::Crypto003),
        })?;

    let artifact = build_artifact(&scenario, &public_key, &public_key_der)?;
    write_file(out_path, &artifact)?;
    Ok(())
}

fn build_artifact(
    scenario: &Scenario,
    org_public_key: &RsaPublicKey,
    org_public_key_der: &[u8],
) -> Result<Vec<u8>, AegisError> {
    let org_key_fp = xxh64(org_public_key_der, 0);

    let session_key = random_session_key();
    let encrypted_session_key = encrypt_session_key(org_public_key, &session_key)?;

    let mut header = [0u8; HEADER_LEN];
    header[0..MAGIC.len()].copy_from_slice(MAGIC.as_slice());
    header[0x05] = VERSION;
    header[0x06] = CIPHER_ID_XCHACHA20;
    let mut kdf_salt = [0u8; KDF_SALT_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut kdf_salt);
    header[KDF_SALT_OFFSET..KDF_SALT_OFFSET + KDF_SALT_LEN].copy_from_slice(&kdf_salt);
    let host_uuid = Uuid::new_v4();
    header[HOST_UUID_OFFSET..HOST_UUID_OFFSET + HOST_UUID_LEN]
        .copy_from_slice(host_uuid.as_bytes());
    header[ORG_KEY_FP_OFFSET..ORG_KEY_FP_OFFSET + 8].copy_from_slice(&org_key_fp.to_be_bytes());

    let mut out = Vec::with_capacity(HEADER_LEN + encrypted_session_key.len() + 4096);
    out.extend_from_slice(&header);
    out.extend_from_slice(&encrypted_session_key);

    let mut plaintext_payloads = Vec::with_capacity(1 + scenario.events.len());
    plaintext_payloads.push(dummy_system_info().encode_to_vec());
    plaintext_payloads.extend(scenario.events.iter().map(event_to_payload_bytes));

    for plaintext in plaintext_payloads {
        let encrypted_chunk = crypto::encrypt(plaintext.as_slice(), session_key.as_slice())?;
        out.extend_from_slice(&encrypted_chunk);
    }

    Ok(out)
}

fn event_to_payload_bytes(event: &EventSpec) -> Vec<u8> {
    match event {
        EventSpec::Process {
            exec_id,
            pid,
            ppid,
            name,
            cmdline,
            exe_path,
            uid,
            start_time,
            is_ghost,
            is_mismatched,
            has_floating_code,
        } => ProcessInfo {
            pid: pid.unwrap_or(1234),
            ppid: ppid.unwrap_or(1),
            name: name.clone().unwrap_or_else(|| "mock-process".to_string()),
            cmdline: cmdline.clone().unwrap_or_else(|| "mock --run".to_string()),
            exe_path: exe_path
                .clone()
                .unwrap_or_else(|| "C:\\\\Windows\\\\System32\\\\cmd.exe".to_string()),
            uid: uid.unwrap_or(0),
            start_time: start_time.unwrap_or_else(timestamp_now),
            is_ghost: is_ghost.unwrap_or(false),
            is_mismatched: is_mismatched.unwrap_or(false),
            has_floating_code: has_floating_code.unwrap_or(false),
            exec_id: *exec_id,
        }
        .encode_to_vec(),

        EventSpec::Telemetry {
            dropped_events,
            timestamp,
            cpu_usage_percent,
            memory_usage_mb,
        } => AgentTelemetry {
            timestamp: timestamp.unwrap_or_else(timestamp_now),
            cpu_usage_percent: cpu_usage_percent.unwrap_or(12),
            memory_usage_mb: memory_usage_mb.unwrap_or(128),
            dropped_events_count: *dropped_events,
        }
        .encode_to_vec(),

        EventSpec::NetworkChange {
            timestamp,
            new_ip_addresses,
        } => NetworkInterfaceUpdate {
            timestamp: timestamp.unwrap_or_else(timestamp_now),
            new_ip_addresses: new_ip_addresses.clone(),
        }
        .encode_to_vec(),
    }
}

fn dummy_system_info() -> SystemInfo {
    SystemInfo {
        hostname: "mock-host".to_string(),
        os_version: "Windows".to_string(),
        kernel_version: "mock-kernel".to_string(),
        ip_addresses: vec!["127.0.0.1".to_string()],
        boot_time: timestamp_now(),
    }
}

fn timestamp_now() -> i64 {
    let dur = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d,
        Err(_) => std::time::Duration::from_secs(0),
    };
    match i64::try_from(dur.as_secs()) {
        Ok(v) => v,
        Err(_) => i64::MAX,
    }
}

fn random_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut key);
    key
}

fn encrypt_session_key(
    org_public_key: &RsaPublicKey,
    session_key: &[u8; 32],
) -> Result<Vec<u8>, AegisError> {
    let mut rng = OsRng;
    org_public_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), session_key.as_slice())
        .map_err(|e| AegisError::CryptoError {
            message: format!("RSA-OAEP 加密 SessionKey 失败: {e}"),
            code: Some(ErrorCode::Crypto003),
        })
}

fn load_rsa_public_key(der_bytes: &[u8]) -> Result<RsaPublicKey, AegisError> {
    RsaPublicKey::from_public_key_der(der_bytes)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(der_bytes))
        .map_err(|e| AegisError::ConfigError {
            message: format!("解析 Org Public Key DER 失败: {e}"),
        })
}

fn write_file(path: &Path, content: &[u8]) -> Result<(), AegisError> {
    let mut file = fs::File::create(path).map_err(|err| io_error_with_path(&err, path))?;
    file.write_all(content)
        .and_then(|()| file.flush())
        .map_err(|err| io_error_with_path(&err, path))
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

#[cfg(test)]
mod tests {
    use super::*;

    use rsa::RsaPrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;

    fn unique_temp_dir() -> Result<PathBuf, AegisError> {
        let base = std::env::temp_dir();
        let id = format!("aegis-mock-{}-{}", std::process::id(), timestamp_now());
        let dir = base.join(id);
        fs::create_dir_all(dir.as_path()).map_err(io_error)?;
        Ok(dir)
    }

    fn load_rsa_private_key(pem: &str) -> Result<RsaPrivateKey, AegisError> {
        let pem = pem.trim_start_matches('\u{feff}').trim();
        RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| AegisError::ConfigError {
                message: format!("解析 Private Key PEM 失败: {e}"),
            })
    }

    fn read_artifact_parts(
        artifact: &[u8],
        rsa_ct_len: usize,
    ) -> Result<(&[u8], &[u8]), AegisError> {
        let rsa_start = HEADER_LEN;
        let rsa_end = rsa_start + rsa_ct_len;
        let rsa_ct = artifact
            .get(rsa_start..rsa_end)
            .ok_or(AegisError::ProtocolError {
                message: "Artifact 长度不足（RSA block）".to_string(),
                code: None,
            })?;
        let stream = artifact.get(rsa_end..).ok_or(AegisError::ProtocolError {
            message: "Artifact 长度不足（stream）".to_string(),
            code: None,
        })?;
        Ok((rsa_ct, stream))
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
            let chunk_len = 24 + 4 + payload_len + 16;
            let chunk =
                stream
                    .get(offset..offset + chunk_len)
                    .ok_or(AegisError::ProtocolError {
                        message: "Artifact chunk 截断".to_string(),
                        code: None,
                    })?;
            offset += chunk_len;

            let plaintext = crypto::decrypt(chunk, session_key.as_slice())?;
            plaintexts.push(plaintext);
        }

        Ok(plaintexts)
    }

    #[test]
    fn generate_then_decrypt_roundtrip() -> Result<(), AegisError> {
        let workspace_root = find_workspace_root(&std::env::current_dir().map_err(io_error)?)
            .ok_or(AegisError::ConfigError {
                message: "无法定位 workspace root".to_string(),
            })?;

        let temp_dir = unique_temp_dir()?;
        let scenario_path = temp_dir.join("scenario.yml");
        let out_path = temp_dir.join("out.aes");

        let scenario_yaml = r#"
events:
  - type: process
    exec_id: 42
    pid: 777
    name: "p1"
  - type: telemetry
    dropped_events: 9
    cpu_usage_percent: 33
    memory_usage_mb: 2048
  - type: network_change
    new_ip_addresses: ["10.0.0.1", "10.0.0.2"]
"#;

        fs::write(scenario_path.as_path(), scenario_yaml).map_err(io_error)?;
        run_with_paths(scenario_path.as_path(), out_path.as_path(), "dev")?;
        let artifact = fs::read(out_path.as_path()).map_err(io_error)?;

        let public_key_der =
            fs::read(workspace_root.join("tests/keys/dev_org_public.der")).map_err(io_error)?;
        let expected_fp = xxh64(public_key_der.as_slice(), 0).to_be_bytes();
        assert_eq!(
            &artifact[ORG_KEY_FP_OFFSET..ORG_KEY_FP_OFFSET + 8],
            expected_fp.as_slice()
        );

        assert_eq!(&artifact[0..MAGIC.len()], MAGIC.as_slice());
        assert_eq!(artifact[0x05], VERSION);
        assert_eq!(artifact[0x06], CIPHER_ID_XCHACHA20);
        assert!(
            artifact[KDF_SALT_OFFSET..KDF_SALT_OFFSET + KDF_SALT_LEN]
                .iter()
                .any(|b| *b != 0)
        );
        assert!(
            artifact[HOST_UUID_OFFSET..HOST_UUID_OFFSET + HOST_UUID_LEN]
                .iter()
                .any(|b| *b != 0)
        );

        let private_key_pem =
            fs::read_to_string(workspace_root.join("tests/keys/dev_org_private.pem"))
                .map_err(io_error)?;
        let private_key = load_rsa_private_key(private_key_pem.as_str())?;

        let rsa_ct_len = private_key.size();
        let (rsa_ct, stream) = read_artifact_parts(artifact.as_slice(), rsa_ct_len)?;

        let session_key_bytes =
            private_key
                .decrypt(Oaep::new::<Sha256>(), rsa_ct)
                .map_err(|e| AegisError::CryptoError {
                    message: format!("RSA-OAEP 解密 SessionKey 失败: {e}"),
                    code: Some(ErrorCode::Crypto003),
                })?;
        let session_key: [u8; 32] =
            session_key_bytes
                .try_into()
                .map_err(|_| AegisError::CryptoError {
                    message: "SessionKey 长度不是 32 bytes".to_string(),
                    code: Some(ErrorCode::Crypto003),
                })?;

        let plaintexts = decrypt_stream_to_plaintexts(stream, &session_key)?;
        if plaintexts.len() < 4 {
            return Err(AegisError::ProtocolError {
                message: "解密后的 Protobuf 消息数量不足".to_string(),
                code: None,
            });
        }

        let system_info = SystemInfo::decode(plaintexts[0].as_slice()).map_err(|e| {
            AegisError::ProtocolError {
                message: format!("SystemInfo Protobuf 反序列化失败: {e}"),
                code: None,
            }
        })?;
        assert!(!system_info.hostname.is_empty());

        let process = ProcessInfo::decode(plaintexts[1].as_slice()).map_err(|e| {
            AegisError::ProtocolError {
                message: format!("ProcessInfo Protobuf 反序列化失败: {e}"),
                code: None,
            }
        })?;
        assert_eq!(process.exec_id, 42);

        let telemetry = AgentTelemetry::decode(plaintexts[2].as_slice()).map_err(|e| {
            AegisError::ProtocolError {
                message: format!("AgentTelemetry Protobuf 反序列化失败: {e}"),
                code: None,
            }
        })?;
        assert_eq!(telemetry.dropped_events_count, 9);

        let net = NetworkInterfaceUpdate::decode(plaintexts[3].as_slice()).map_err(|e| {
            AegisError::ProtocolError {
                message: format!("NetworkInterfaceUpdate Protobuf 反序列化失败: {e}"),
                code: None,
            }
        })?;
        assert_eq!(net.new_ip_addresses.len(), 2);
        Ok(())
    }
}
