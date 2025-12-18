#![allow(missing_docs)]

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_kw::Kek;
use argon2::{Algorithm, Argon2, Params, Version};
use clap::Parser;
use common::crypto;
use common::error::{AegisError, ErrorCode};
use common::protocol::{AgentTelemetry, NetworkInterfaceUpdate, ProcessInfo, SystemInfo};
use prost::Message;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
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
const USER_SLOT_LEN: usize = 40;

#[derive(Parser, Debug)]
#[command(name = "mock", version)]
struct Cli {
    #[arg(long = "scenario")]
    scenario: PathBuf,

    #[arg(long = "out")]
    out: PathBuf,

    #[arg(long = "mode", default_value = "dev")]
    mode: String,

    #[arg(long = "cert")]
    cert: Option<PathBuf>,

    #[arg(long = "password")]
    password: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct Scenario {
    #[serde(default, rename = "scenario_name")]
    name: Option<String>,
    #[serde(default = "default_base_time")]
    base_time: String,
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
        #[serde(default)]
        start_offset: Option<String>,
        is_ghost: Option<bool>,
        is_mismatched: Option<bool>,
        has_floating_code: Option<bool>,
    },

    #[serde(rename = "telemetry")]
    Telemetry {
        dropped_events: u64,
        timestamp: Option<i64>,
        #[serde(default)]
        time_offset: Option<String>,
        #[serde(alias = "cpu")]
        cpu_usage_percent: Option<u32>,
        memory_usage_mb: Option<u32>,
    },

    #[serde(rename = "network_change")]
    NetworkChange {
        timestamp: Option<i64>,
        #[serde(default)]
        time_offset: Option<String>,
        #[serde(alias = "new_ips")]
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
    run_with_paths(
        &cli.scenario,
        &cli.out,
        cli.mode.as_str(),
        cli.cert.as_deref(),
        cli.password.as_deref(),
    )
}

fn default_dev_keys_dir() -> PathBuf {
    std::env::temp_dir().join("aegis").join("dev_keys")
}

fn load_or_generate_default_dev_public_key_der() -> Result<Vec<u8>, AegisError> {
    let dir = default_dev_keys_dir();
    let path = dir.join("dev_org_public.der");
    if path.exists() {
        return fs::read(path.as_path()).map_err(|err| io_error_with_path(&err, path.as_path()));
    }

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).map_err(|e| AegisError::CryptoError {
        message: format!("生成 dev RSA 私钥失败: {e}"),
        code: Some(ErrorCode::Crypto003),
    })?;
    let public_key = RsaPublicKey::from(&private_key);
    let public_key_der = public_key
        .to_public_key_der()
        .map_err(|e| AegisError::CryptoError {
            message: format!("导出 dev Org Public Key DER 失败: {e}"),
            code: Some(ErrorCode::Crypto003),
        })?
        .as_bytes()
        .to_vec();

    fs::create_dir_all(dir.as_path()).map_err(io_error)?;
    fs::write(path.as_path(), public_key_der.as_slice()).map_err(io_error)?;
    Ok(public_key_der)
}

fn run_with_paths(
    scenario_path: &Path,
    out_path: &Path,
    mode: &str,
    cert_path: Option<&Path>,
    password: Option<&str>,
) -> Result<(), AegisError> {
    if mode != "dev" && mode != "prod" {
        return Err(AegisError::ConfigError {
            message: format!("不支持的 mode: {mode}，仅支持 dev/prod"),
        });
    }

    let (public_key, public_key_der) = match mode {
        "dev" => {
            if let Some(cert_path) = cert_path {
                let public_key_der =
                    fs::read(cert_path).map_err(|err| io_error_with_path(&err, cert_path))?;
                let public_key = load_rsa_public_key(&public_key_der)?;
                (public_key, public_key_der)
            } else {
                let workspace_root = find_workspace_root(
                    &std::env::current_dir().map_err(io_error)?,
                )
                .ok_or(AegisError::ConfigError {
                    message: "无法定位 workspace root（未找到包含 [workspace] 的 Cargo.toml）"
                        .to_string(),
                })?;
                let public_key_path = workspace_root.join("tests/keys/dev_org_public.der");
                let public_key_der = if public_key_path.exists() {
                    fs::read(&public_key_path)
                        .map_err(|err| io_error_with_path(&err, &public_key_path))?
                } else {
                    load_or_generate_default_dev_public_key_der()?
                };
                let public_key = load_rsa_public_key(&public_key_der)?;
                (public_key, public_key_der)
            }
        }
        "prod" => {
            let cert_path = cert_path.ok_or(AegisError::ConfigError {
                message: "prod 模式必须提供 --cert <org_public.der>".to_string(),
            })?;
            let public_key_der =
                fs::read(cert_path).map_err(|err| io_error_with_path(&err, cert_path))?;
            let public_key = load_rsa_public_key(&public_key_der)?;
            (public_key, public_key_der)
        }
        _ => {
            return Err(AegisError::ConfigError {
                message: format!("不支持的 mode: {mode}"),
            });
        }
    };

    let scenario_bytes =
        fs::read(scenario_path).map_err(|err| io_error_with_path(&err, scenario_path))?;
    let scenario: Scenario =
        serde_yaml::from_slice(&scenario_bytes).map_err(|e| AegisError::ProtocolError {
            message: format!("Scenario YAML 解析失败: {e}"),
            code: Some(ErrorCode::Crypto003),
        })?;

    let password = resolve_password(mode, password)?;
    let artifact = build_artifact(
        mode,
        &scenario,
        &public_key,
        &public_key_der,
        password.as_str(),
    )?;
    for warning in artifact.warnings {
        eprintln!("{warning}");
    }
    write_file(out_path, &artifact.bytes)?;
    Ok(())
}

struct BuildArtifactResult {
    bytes: Vec<u8>,
    warnings: Vec<String>,
}

fn build_artifact(
    mode: &str,
    scenario: &Scenario,
    org_public_key: &RsaPublicKey,
    org_public_key_der: &[u8],
    password: &str,
) -> Result<BuildArtifactResult, AegisError> {
    let _scenario_name = scenario.name.as_deref();
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
    let host_uuid = get_or_create_host_uuid(mode)?;
    header[HOST_UUID_OFFSET..HOST_UUID_OFFSET + HOST_UUID_LEN].copy_from_slice(host_uuid.as_ref());
    header[ORG_KEY_FP_OFFSET..ORG_KEY_FP_OFFSET + 8].copy_from_slice(&org_key_fp.to_be_bytes());

    let user_slot = encrypt_session_key_user_slot(password, &kdf_salt, &session_key)?;

    let mut out =
        Vec::with_capacity(HEADER_LEN + USER_SLOT_LEN + encrypted_session_key.len() + 4096);
    out.extend_from_slice(&header);
    out.extend_from_slice(user_slot.as_slice());
    out.extend_from_slice(&encrypted_session_key);

    let base_time = parse_base_time(scenario.base_time.as_str())?;
    let mut warnings = Vec::new();
    let mut any_data_loss = false;
    let mut last_net_timestamp: Option<i64> = None;

    let encrypted_chunk = crypto::encrypt(
        dummy_system_info().encode_to_vec().as_slice(),
        session_key.as_slice(),
    )?;
    out.extend_from_slice(&encrypted_chunk);

    for event in &scenario.events {
        let plaintext = event_to_payload_bytes(
            event,
            base_time,
            &mut any_data_loss,
            &mut last_net_timestamp,
        )?;
        let encrypted_chunk = crypto::encrypt(plaintext.as_slice(), session_key.as_slice())?;
        out.extend_from_slice(&encrypted_chunk);
    }

    if any_data_loss {
        warnings.push("WARN: Trace file contains data loss events".to_string());
    }

    crypto::append_hmac_sig_trailer_v1(&mut out, &session_key)?;

    Ok(BuildArtifactResult {
        bytes: out,
        warnings,
    })
}

fn resolve_event_timestamp(
    base_time: i64,
    timestamp: Option<i64>,
    time_offset: Option<&str>,
) -> i64 {
    timestamp.unwrap_or_else(|| {
        time_offset
            .and_then(|s| apply_offset(base_time, s).ok())
            .unwrap_or(base_time)
    })
}

fn event_to_payload_bytes(
    event: &EventSpec,
    base_time: i64,
    any_data_loss: &mut bool,
    last_net_timestamp: &mut Option<i64>,
) -> Result<Vec<u8>, AegisError> {
    let bytes = match event {
        EventSpec::Process {
            exec_id,
            pid,
            ppid,
            name,
            cmdline,
            exe_path,
            uid,
            start_time,
            start_offset,
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
            start_time: resolve_event_timestamp(base_time, *start_time, start_offset.as_deref()),
            is_ghost: is_ghost.unwrap_or(false),
            is_mismatched: is_mismatched.unwrap_or(false),
            has_floating_code: has_floating_code.unwrap_or(false),
            exec_id: *exec_id,
        }
        .encode_to_vec(),

        EventSpec::Telemetry {
            dropped_events,
            timestamp,
            time_offset,
            cpu_usage_percent,
            memory_usage_mb,
        } => {
            if *dropped_events > 0 {
                *any_data_loss = true;
            }
            AgentTelemetry {
                timestamp: resolve_event_timestamp(base_time, *timestamp, time_offset.as_deref()),
                cpu_usage_percent: cpu_usage_percent.unwrap_or(12),
                memory_usage_mb: memory_usage_mb.unwrap_or(128),
                dropped_events_count: *dropped_events,
            }
            .encode_to_vec()
        }
        EventSpec::NetworkChange {
            timestamp,
            time_offset,
            new_ip_addresses,
        } => {
            let ts = resolve_event_timestamp(base_time, *timestamp, time_offset.as_deref());
            if let Some(prev) = *last_net_timestamp
                && ts <= prev
            {
                return Err(AegisError::ProtocolError {
                    message: "NetworkInterfaceUpdate 时间戳必须单调递增".to_string(),
                    code: None,
                });
            }
            *last_net_timestamp = Some(ts);
            NetworkInterfaceUpdate {
                timestamp: ts,
                new_ip_addresses: new_ip_addresses.clone(),
            }
            .encode_to_vec()
        }
    };
    Ok(bytes)
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
    i64::try_from(dur.as_secs()).unwrap_or(i64::MAX)
}

fn default_base_time() -> String {
    "now".to_string()
}

fn parse_base_time(base_time: &str) -> Result<i64, AegisError> {
    let base_time = base_time.trim();
    if base_time.eq_ignore_ascii_case("now") {
        return Ok(timestamp_now());
    }
    base_time
        .parse::<i64>()
        .map_err(|_| AegisError::ConfigError {
            message: format!("无法解析 base_time: {base_time}"),
        })
}

fn apply_offset(base: i64, offset: &str) -> Result<i64, AegisError> {
    let offset = offset.trim();
    if offset.is_empty() {
        return Ok(base);
    }

    let (sign, rest) = match offset.as_bytes().first().copied() {
        Some(b'-') => (-1i64, &offset[1..]),
        Some(b'+') => (1i64, &offset[1..]),
        _ => (1i64, offset),
    };

    let (num_part, unit) = match rest.chars().last() {
        Some('s' | 'm' | 'h') => (
            &rest[..rest.len() - 1],
            rest[rest.len() - 1..].chars().next(),
        ),
        _ => (rest, None),
    };

    let magnitude = num_part
        .trim()
        .parse::<i64>()
        .map_err(|_| AegisError::ConfigError {
            message: format!("无法解析 offset: {offset}"),
        })?;

    let multiplier = match unit {
        Some('m') => 60i64,
        Some('h') => 3600i64,
        Some('s') | None => 1i64,
        Some(_) => {
            return Err(AegisError::ConfigError {
                message: format!("不支持的 offset 单位: {offset}"),
            });
        }
    };

    base.checked_add(sign.saturating_mul(magnitude.saturating_mul(multiplier)))
        .ok_or(AegisError::ProtocolError {
            message: "offset 计算溢出".to_string(),
            code: None,
        })
}

fn random_session_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut key);
    key
}

fn resolve_password(mode: &str, password: Option<&str>) -> Result<String, AegisError> {
    match (mode, password) {
        ("dev", None) => Ok(match std::env::var("AEGIS_DEV_PASSWORD") {
            Ok(v) => v,
            Err(_) => Uuid::new_v4().to_string(),
        }),
        ("dev" | "prod", Some(p)) => Ok(p.to_string()),
        ("prod", None) => Err(AegisError::ConfigError {
            message: "prod 模式必须提供 --password".to_string(),
        }),
        _ => Err(AegisError::ConfigError {
            message: format!("不支持的 mode: {mode}"),
        }),
    }
}

fn encrypt_session_key_user_slot(
    password: &str,
    kdf_salt: &[u8; KDF_SALT_LEN],
    session_key: &[u8; 32],
) -> Result<Vec<u8>, AegisError> {
    let kek_bytes = derive_kek(password.as_bytes(), kdf_salt)?;
    let kek = Kek::from(kek_bytes);
    let wrapped = kek
        .wrap_vec(session_key.as_slice())
        .map_err(|e| AegisError::CryptoError {
            message: format!("AES-256-KeyWrap 加密 SessionKey 失败: {e}"),
            code: Some(ErrorCode::Crypto003),
        })?;
    if wrapped.len() != USER_SLOT_LEN {
        return Err(AegisError::CryptoError {
            message: "AES-256-KeyWrap 输出长度异常".to_string(),
            code: Some(ErrorCode::Crypto003),
        });
    }
    Ok(wrapped)
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

fn get_or_create_host_uuid(mode: &str) -> Result<[u8; 16], AegisError> {
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
        use winreg::enums::HKEY_LOCAL_MACHINE;
        if let Some(v) =
            try_read_host_uuid_registry(HKEY_LOCAL_MACHINE).map_err(AegisError::IoError)?
        {
            return Ok(Some(v));
        }
        if mode == "dev" {
            use winreg::enums::HKEY_CURRENT_USER;
            return try_read_host_uuid_registry(HKEY_CURRENT_USER).map_err(AegisError::IoError);
        }
        Ok(None)
    }

    #[cfg(not(windows))]
    {
        let primary = Path::new("/etc/aegis/uuid");
        if let Some(v) = try_read_host_uuid_file(primary).map_err(AegisError::IoError)? {
            return Ok(Some(v));
        }
        if mode == "dev" {
            let fallback = user_uuid_path();
            if let Some(v) =
                try_read_host_uuid_file(fallback.as_path()).map_err(AegisError::IoError)?
            {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }
}

fn persist_host_uuid(mode: &str, uuid: &[u8; 16]) -> Result<(), AegisError> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        if try_write_host_uuid_registry(HKEY_LOCAL_MACHINE, uuid).is_ok() {
            return Ok(());
        }
        if mode == "dev" {
            use winreg::enums::HKEY_CURRENT_USER;
            if try_write_host_uuid_registry(HKEY_CURRENT_USER, uuid).is_ok() {
                return Ok(());
            }
            return Err(AegisError::ConfigError {
                message: "无法写入 HostUUID 至 HKLM/HKCU\\SOFTWARE\\Aegis（请以管理员权限运行）"
                    .to_string(),
            });
        }
        Err(AegisError::ConfigError {
            message: "无法写入 HostUUID 至 HKLM\\SOFTWARE\\Aegis（请以管理员权限运行）".to_string(),
        })
    }

    #[cfg(not(windows))]
    {
        let primary = Path::new("/etc/aegis/uuid");
        if try_write_host_uuid_file(primary, uuid).is_ok() {
            return Ok(());
        }
        if mode != "dev" {
            return Err(AegisError::ConfigError {
                message: "无法写入 HostUUID 至 /etc/aegis/uuid（请以 root 权限运行）".to_string(),
            });
        }
        let fallback = user_uuid_path();
        try_write_host_uuid_file(fallback.as_path(), uuid).map_err(AegisError::IoError)
    }
}

#[cfg(windows)]
fn try_read_host_uuid_registry(hive: winreg::HKEY) -> io::Result<Option<[u8; 16]>> {
    use winreg::RegKey;
    let root = RegKey::predef(hive);
    let key = match root.open_subkey("SOFTWARE\\Aegis") {
        Ok(k) => k,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    let uuid_str: String = match key.get_value("HostUUID") {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
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
fn try_read_host_uuid_file(path: &Path) -> io::Result<Option<[u8; 16]>> {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let Ok(arr) = bytes.as_slice().try_into() else {
        return Ok(None);
    };
    Ok(Some(arr))
}

#[cfg(not(windows))]
fn try_write_host_uuid_file(path: &Path, uuid: &[u8; 16]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, uuid)
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

    use common::protocol::{MessagePayload, validate_first_chunk_is_system_info};
    use rsa::RsaPrivateKey;
    use rsa::RsaPublicKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::traits::PublicKeyParts;

    type ArtifactParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

    fn test_passphrase() -> String {
        Uuid::new_v4().to_string()
    }

    fn unique_temp_dir() -> Result<PathBuf, AegisError> {
        let base = std::env::temp_dir();
        let id = format!("aegis-mock-{}-{}", std::process::id(), timestamp_now());
        let dir = base.join(id);
        fs::create_dir_all(dir.as_path()).map_err(io_error)?;
        Ok(dir)
    }

    fn read_artifact_parts(
        artifact: &[u8],
        rsa_ct_len: usize,
    ) -> Result<ArtifactParts<'_>, AegisError> {
        let user_slot_start = HEADER_LEN;
        let user_slot_end = user_slot_start + USER_SLOT_LEN;
        let user_slot =
            artifact
                .get(user_slot_start..user_slot_end)
                .ok_or(AegisError::ProtocolError {
                    message: "Artifact 长度不足（User slot）".to_string(),
                    code: None,
                })?;

        let rsa_start = user_slot_end;
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
        Ok((user_slot, rsa_ct, stream))
    }

    fn decrypt_stream_to_plaintexts(
        stream: &[u8],
        session_key: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, AegisError> {
        const MAX_CHUNK_PAYLOAD_LEN: usize = 50 * 1024 * 1024;
        let mut offset = 0usize;
        let mut plaintexts = Vec::new();

        while offset < stream.len() {
            if stream.len().saturating_sub(offset) < 24 + 4 + 16 {
                break;
            }

            let Some(len_bytes) = stream.get(offset + 24..offset + 28) else {
                break;
            };
            let payload_len =
                u32::from_be_bytes(
                    len_bytes
                        .try_into()
                        .map_err(|_| AegisError::ProtocolError {
                            message: "读取 payload_len 失败".to_string(),
                            code: None,
                        })?,
                ) as usize;
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
            let end = offset
                .checked_add(chunk_len)
                .ok_or(AegisError::ProtocolError {
                    message: "Artifact offset 溢出".to_string(),
                    code: None,
                })?;
            let Some(chunk) = stream.get(offset..end) else {
                break;
            };
            offset += chunk_len;

            let plaintext = crypto::decrypt(chunk, session_key.as_slice())?;
            plaintexts.push(plaintext);
        }

        Ok(plaintexts)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generate_then_decrypt_roundtrip() -> Result<(), AegisError> {
        #[cfg(windows)]
        {
            use winreg::RegKey;
            use winreg::enums::HKEY_LOCAL_MACHINE;

            let root = RegKey::predef(HKEY_LOCAL_MACHINE);
            let Ok((key, _)) = root.create_subkey("SOFTWARE\\Aegis") else {
                return Ok(());
            };
            let uuid_str = Uuid::new_v4().to_string();
            if key.set_value("HostUUID", &uuid_str).is_err() {
                return Ok(());
            }
        }

        let temp_dir = unique_temp_dir()?;
        let scenario_path = temp_dir.join("scenario.yml");
        let out_path = temp_dir.join("out.aes");
        let cert_path = temp_dir.join("org_public.der");

        let passphrase = test_passphrase();
        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| AegisError::CryptoError {
                message: format!("生成 RSA 私钥失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| AegisError::CryptoError {
                message: format!("导出 Org Public Key DER 失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?
            .as_bytes()
            .to_vec();
        fs::write(cert_path.as_path(), public_key_der.as_slice()).map_err(io_error)?;

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
        run_with_paths(
            scenario_path.as_path(),
            out_path.as_path(),
            "dev",
            Some(cert_path.as_path()),
            Some(passphrase.as_str()),
        )?;
        let artifact = fs::read(out_path.as_path()).map_err(io_error)?;

        let expected_fp = xxh64(public_key_der.as_slice(), 0).to_be_bytes();
        assert_eq!(
            &artifact[ORG_KEY_FP_OFFSET..ORG_KEY_FP_OFFSET + 8],
            expected_fp.as_slice()
        );

        assert_eq!(&artifact[0..MAGIC.len()], MAGIC.as_slice());
        assert_eq!(artifact[0x05], VERSION);
        assert_eq!(artifact[0x06], CIPHER_ID_XCHACHA20);
        assert_eq!(artifact[0x07], 0);
        assert!(
            artifact[0x40..0x40 + 80].iter().all(|b| *b == 0),
            "Reserved 区必须全 0"
        );
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

        let rsa_ct_len = private_key.size();
        let (user_slot, rsa_ct, stream) = read_artifact_parts(artifact.as_slice(), rsa_ct_len)?;
        let first_payload_len = u32::from_be_bytes(
            stream
                .get(24..28)
                .ok_or(AegisError::ProtocolError {
                    message: "读取 payload_len 失败".to_string(),
                    code: None,
                })?
                .try_into()
                .map_err(|_| AegisError::ProtocolError {
                    message: "读取 payload_len 失败".to_string(),
                    code: None,
                })?,
        ) as usize;
        let first_chunk_len = 24usize + 4 + first_payload_len + 16;
        assert!(stream.len() >= first_chunk_len);

        let kdf_salt: [u8; KDF_SALT_LEN] = artifact
            [KDF_SALT_OFFSET..KDF_SALT_OFFSET + KDF_SALT_LEN]
            .try_into()
            .map_err(|_| AegisError::ProtocolError {
                message: "读取 KDF_Salt 失败".to_string(),
                code: None,
            })?;
        let kek_bytes = derive_kek(passphrase.as_bytes(), kdf_salt.as_ref())?;
        let kek = Kek::from(kek_bytes);
        let unwrapped = kek
            .unwrap_vec(user_slot)
            .map_err(|e| AegisError::CryptoError {
                message: format!("AES-256-KeyWrap 解密 SessionKey 失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?;
        let session_key_from_user: [u8; 32] =
            unwrapped
                .as_slice()
                .try_into()
                .map_err(|_| AegisError::CryptoError {
                    message: "User Slot 解出的 SessionKey 长度不是 32 bytes".to_string(),
                    code: Some(ErrorCode::Crypto003),
                })?;

        let session_key_bytes =
            private_key
                .decrypt(Oaep::new::<Sha256>(), rsa_ct)
                .map_err(|e| AegisError::CryptoError {
                    message: format!("RSA-OAEP 解密 SessionKey 失败: {e}"),
                    code: Some(ErrorCode::Crypto003),
                })?;
        let session_key_from_org: [u8; 32] =
            session_key_bytes
                .try_into()
                .map_err(|_| AegisError::CryptoError {
                    message: "SessionKey 长度不是 32 bytes".to_string(),
                    code: Some(ErrorCode::Crypto003),
                })?;

        assert_eq!(session_key_from_user, session_key_from_org);

        assert_eq!(
            crypto::verify_hmac_sig_trailer_v1(artifact.as_slice(), &session_key_from_org)?,
            crypto::HmacSigVerification::Valid
        );

        let plaintexts = decrypt_stream_to_plaintexts(stream, &session_key_from_org)?;
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
        validate_first_chunk_is_system_info(&MessagePayload::SystemInfo(system_info.clone()))?;
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

    #[test]
    fn warns_on_data_loss_events() -> Result<(), AegisError> {
        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| AegisError::CryptoError {
                message: format!("生成 RSA 私钥失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| AegisError::CryptoError {
                message: format!("导出 Org Public Key DER 失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?
            .as_bytes()
            .to_vec();

        let scenario = Scenario {
            name: None,
            base_time: "1000".to_string(),
            events: vec![EventSpec::Telemetry {
                dropped_events: 1,
                timestamp: Some(1000),
                time_offset: None,
                cpu_usage_percent: Some(85),
                memory_usage_mb: Some(512),
            }],
        };

        let passphrase = test_passphrase();
        let artifact = build_artifact(
            "dev",
            &scenario,
            &public_key,
            public_key_der.as_slice(),
            passphrase.as_str(),
        )?;
        assert!(
            artifact
                .warnings
                .iter()
                .any(|w| w.as_str() == "WARN: Trace file contains data loss events")
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn dev_mode_without_cert_works_with_fallback_key() -> Result<(), AegisError> {
        #[cfg(windows)]
        {
            use winreg::RegKey;
            use winreg::enums::HKEY_CURRENT_USER;

            let root = RegKey::predef(HKEY_CURRENT_USER);
            let Ok((key, _)) = root.create_subkey("SOFTWARE\\Aegis") else {
                return Ok(());
            };
            let uuid_str = Uuid::new_v4().to_string();
            if key.set_value("HostUUID", &uuid_str).is_err() {
                return Ok(());
            }
        }

        let temp_dir = unique_temp_dir()?;
        let scenario_path = temp_dir.join("scenario.yml");
        let out_path = temp_dir.join("out.aes");
        let scenario_yaml = r#"
events:
  - type: process
    exec_id: 1
    pid: 2
    name: "p"
"#;
        fs::write(scenario_path.as_path(), scenario_yaml).map_err(io_error)?;

        run_with_paths(
            scenario_path.as_path(),
            out_path.as_path(),
            "dev",
            None,
            None,
        )?;
        let out = fs::read(out_path.as_path()).map_err(io_error)?;
        assert!(out.len() > HEADER_LEN);
        Ok(())
    }

    #[test]
    #[cfg(windows)]
    fn host_uuid_is_persisted_in_dev_mode() -> Result<(), AegisError> {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;

        let root = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = root.create_subkey("SOFTWARE\\Aegis").map_err(io_error)?;
        let expected = Uuid::new_v4().to_string();
        key.set_value("HostUUID", &expected).map_err(io_error)?;

        let first = get_or_create_host_uuid("dev")?;
        assert_eq!(Uuid::from_bytes(first).to_string(), expected);

        let second = get_or_create_host_uuid("dev")?;
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn decrypt_rejects_payload_len_over_50mb() {
        let too_big_payload_len_u32: u32 = 50 * 1024 * 1024 + 1;
        let mut stream = vec![0u8; 24 + 4 + 16];
        stream[24..28].copy_from_slice(&too_big_payload_len_u32.to_be_bytes());
        let key = [0u8; 32];
        let err = decrypt_stream_to_plaintexts(stream.as_slice(), &key).err();
        assert!(matches!(
            err,
            Some(AegisError::PacketTooLarge { size, limit })
                if size == (50 * 1024 * 1024 + 1) as usize && limit == 50 * 1024 * 1024
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn decrypt_tolerates_truncated_last_chunk() -> Result<(), AegisError> {
        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| AegisError::CryptoError {
                message: format!("生成 RSA 私钥失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| AegisError::CryptoError {
                message: format!("导出 Org Public Key DER 失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?
            .as_bytes()
            .to_vec();

        let scenario = Scenario {
            name: None,
            base_time: "1000".to_string(),
            events: vec![EventSpec::Telemetry {
                dropped_events: 0,
                timestamp: Some(1000),
                time_offset: None,
                cpu_usage_percent: Some(10),
                memory_usage_mb: Some(128),
            }],
        };

        let artifact = build_artifact(
            "dev",
            &scenario,
            &public_key,
            public_key_der.as_slice(),
            "aegis-dev",
        )?;

        let rsa_ct_len = private_key.size();
        let (user_slot, rsa_ct, stream) =
            read_artifact_parts(artifact.bytes.as_slice(), rsa_ct_len)?;
        let kdf_salt: [u8; KDF_SALT_LEN] = artifact.bytes
            [KDF_SALT_OFFSET..KDF_SALT_OFFSET + KDF_SALT_LEN]
            .try_into()
            .map_err(|_| AegisError::ProtocolError {
                message: "读取 KDF_Salt 失败".to_string(),
                code: None,
            })?;
        let kek_bytes = derive_kek("aegis-dev".as_bytes(), kdf_salt.as_ref())?;
        let kek = Kek::from(kek_bytes);
        let unwrapped = kek
            .unwrap_vec(user_slot)
            .map_err(|e| AegisError::CryptoError {
                message: format!("AES-256-KeyWrap 解密 SessionKey 失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?;
        let session_key_from_user: [u8; 32] =
            unwrapped
                .as_slice()
                .try_into()
                .map_err(|_| AegisError::CryptoError {
                    message: "User Slot 解出的 SessionKey 长度不是 32 bytes".to_string(),
                    code: Some(ErrorCode::Crypto003),
                })?;

        let session_key_bytes =
            private_key
                .decrypt(Oaep::new::<Sha256>(), rsa_ct)
                .map_err(|e| AegisError::CryptoError {
                    message: format!("RSA-OAEP 解密 SessionKey 失败: {e}"),
                    code: Some(ErrorCode::Crypto003),
                })?;
        let session_key_from_org: [u8; 32] =
            session_key_bytes
                .try_into()
                .map_err(|_| AegisError::CryptoError {
                    message: "SessionKey 长度不是 32 bytes".to_string(),
                    code: Some(ErrorCode::Crypto003),
                })?;
        assert_eq!(session_key_from_user, session_key_from_org);

        assert_eq!(
            crypto::verify_hmac_sig_trailer_v1(artifact.bytes.as_slice(), &session_key_from_org)?,
            crypto::HmacSigVerification::Valid
        );

        let stream_data_end = if stream.len() >= crypto::HMAC_SIG_TRAILER_LEN {
            let start = stream.len().saturating_sub(crypto::HMAC_SIG_TRAILER_LEN);
            match stream.get(start..start + crypto::HMAC_SIG_MAGIC.len()) {
                Some(magic) if magic == crypto::HMAC_SIG_MAGIC.as_slice() => start,
                _ => stream.len(),
            }
        } else {
            stream.len()
        };

        let stream_data = stream
            .get(..stream_data_end)
            .ok_or(AegisError::ProtocolError {
                message: "stream_data 越界".to_string(),
                code: None,
            })?;

        let full_plaintexts = decrypt_stream_to_plaintexts(stream_data, &session_key_from_org)?;
        assert!(full_plaintexts.len() >= 2);

        let truncated_stream = stream_data
            .get(..stream_data.len().saturating_sub(1))
            .ok_or(AegisError::ProtocolError {
                message: "stream 为空".to_string(),
                code: None,
            })?;
        let truncated_plaintexts =
            decrypt_stream_to_plaintexts(truncated_stream, &session_key_from_org)?;

        assert_eq!(truncated_plaintexts.len() + 1, full_plaintexts.len());
        let _ = SystemInfo::decode(truncated_plaintexts[0].as_slice()).map_err(|e| {
            AegisError::ProtocolError {
                message: format!("SystemInfo Protobuf 反序列化失败: {e}"),
                code: None,
            }
        })?;
        Ok(())
    }

    #[test]
    fn network_update_timestamps_must_increase() -> Result<(), AegisError> {
        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| AegisError::CryptoError {
                message: format!("生成 RSA 私钥失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| AegisError::CryptoError {
                message: format!("导出 Org Public Key DER 失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?
            .as_bytes()
            .to_vec();

        let scenario = Scenario {
            name: None,
            base_time: "1000".to_string(),
            events: vec![
                EventSpec::NetworkChange {
                    timestamp: Some(2000),
                    time_offset: None,
                    new_ip_addresses: vec!["10.0.0.1".to_string()],
                },
                EventSpec::NetworkChange {
                    timestamp: Some(1999),
                    time_offset: None,
                    new_ip_addresses: vec!["10.0.0.2".to_string()],
                },
            ],
        };

        let passphrase = test_passphrase();
        let err = build_artifact(
            "dev",
            &scenario,
            &public_key,
            public_key_der.as_slice(),
            passphrase.as_str(),
        )
        .err();
        assert!(matches!(err, Some(AegisError::ProtocolError { .. })));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generate_then_decrypt_roundtrip_with_repo_dev_keys() -> Result<(), AegisError> {
        #[cfg(windows)]
        {
            use winreg::RegKey;
            use winreg::enums::HKEY_CURRENT_USER;

            let root = RegKey::predef(HKEY_CURRENT_USER);
            let Ok((key, _)) = root.create_subkey("SOFTWARE\\Aegis") else {
                return Ok(());
            };
            let uuid_str = Uuid::new_v4().to_string();
            if key.set_value("HostUUID", &uuid_str).is_err() {
                return Ok(());
            }
        }
        let workspace_root = find_workspace_root(&std::env::current_dir().map_err(io_error)?)
            .ok_or(AegisError::ConfigError {
                message: "无法定位 workspace root（未找到包含 [workspace] 的 Cargo.toml）"
                    .to_string(),
            })?;
        let public_key_path = workspace_root.join("tests/keys/dev_org_public.der");
        let private_key_path = workspace_root.join("tests/keys/dev_org_private.pem");

        let temp_dir = unique_temp_dir()?;
        let scenario_path = temp_dir.join("scenario.yml");
        let out_path = temp_dir.join("out.aes");
        let passphrase = test_passphrase();
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
    timestamp: 100
    new_ip_addresses: ["10.0.0.1", "10.0.0.2"]
"#;
        fs::write(scenario_path.as_path(), scenario_yaml).map_err(io_error)?;

        let (expected_public_der, private_key) = if public_key_path.exists()
            && private_key_path.exists()
        {
            run_with_paths(
                scenario_path.as_path(),
                out_path.as_path(),
                "dev",
                None,
                Some(passphrase.as_str()),
            )?;
            let public_der = fs::read(public_key_path.as_path()).map_err(io_error)?;
            let private_pem = fs::read_to_string(private_key_path.as_path()).map_err(io_error)?;
            let private_pem = private_pem.trim().trim_start_matches('\u{feff}');
            let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem)
                .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_pem))
                .map_err(|e| AegisError::CryptoError {
                    message: format!("解析 dev_org_private.pem 失败: {e}"),
                    code: Some(ErrorCode::Crypto003),
                })?;
            (public_der, private_key)
        } else {
            let mut rng = OsRng;
            let private_key =
                RsaPrivateKey::new(&mut rng, 2048).map_err(|e| AegisError::CryptoError {
                    message: format!("生成 dev RSA 私钥失败: {e}"),
                    code: Some(ErrorCode::Crypto003),
                })?;
            let public_key = RsaPublicKey::from(&private_key);
            let public_key_der = public_key
                .to_public_key_der()
                .map_err(|e| AegisError::CryptoError {
                    message: format!("导出 dev Org Public Key DER 失败: {e}"),
                    code: Some(ErrorCode::Crypto003),
                })?
                .as_bytes()
                .to_vec();

            let cert_path = temp_dir.join("dev_org_public.der");
            fs::write(cert_path.as_path(), public_key_der.as_slice()).map_err(io_error)?;
            run_with_paths(
                scenario_path.as_path(),
                out_path.as_path(),
                "dev",
                Some(cert_path.as_path()),
                Some(passphrase.as_str()),
            )?;
            (public_key_der, private_key)
        };

        let artifact = fs::read(out_path.as_path()).map_err(io_error)?;
        let expected_fp = xxh64(expected_public_der.as_slice(), 0).to_be_bytes();
        assert_eq!(
            &artifact[ORG_KEY_FP_OFFSET..ORG_KEY_FP_OFFSET + 8],
            expected_fp.as_slice()
        );
        let rsa_ct_len = private_key.size();
        let (user_slot, rsa_ct, stream) = read_artifact_parts(artifact.as_slice(), rsa_ct_len)?;
        let kdf_salt: [u8; KDF_SALT_LEN] = artifact
            [KDF_SALT_OFFSET..KDF_SALT_OFFSET + KDF_SALT_LEN]
            .try_into()
            .map_err(|_| AegisError::ProtocolError {
                message: "读取 KDF_Salt 失败".to_string(),
                code: None,
            })?;
        let kek_bytes = derive_kek(passphrase.as_bytes(), kdf_salt.as_ref())?;
        let kek = Kek::from(kek_bytes);
        let unwrapped = kek
            .unwrap_vec(user_slot)
            .map_err(|e| AegisError::CryptoError {
                message: format!("AES-256-KeyWrap 解密 SessionKey 失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?;
        let session_key_from_user: [u8; 32] =
            unwrapped
                .as_slice()
                .try_into()
                .map_err(|_| AegisError::CryptoError {
                    message: "User Slot 解出的 SessionKey 长度不是 32 bytes".to_string(),
                    code: Some(ErrorCode::Crypto003),
                })?;
        let session_key_bytes =
            private_key
                .decrypt(Oaep::new::<Sha256>(), rsa_ct)
                .map_err(|e| AegisError::CryptoError {
                    message: format!("RSA-OAEP 解密 SessionKey 失败: {e}"),
                    code: Some(ErrorCode::Crypto003),
                })?;
        let session_key_from_org: [u8; 32] =
            session_key_bytes
                .try_into()
                .map_err(|_| AegisError::CryptoError {
                    message: "SessionKey 长度不是 32 bytes".to_string(),
                    code: Some(ErrorCode::Crypto003),
                })?;
        assert_eq!(session_key_from_user, session_key_from_org);

        assert_eq!(
            crypto::verify_hmac_sig_trailer_v1(artifact.as_slice(), &session_key_from_org)?,
            crypto::HmacSigVerification::Valid
        );

        let plaintexts = decrypt_stream_to_plaintexts(stream, &session_key_from_org)?;
        let system_info = SystemInfo::decode(plaintexts[0].as_slice()).map_err(|e| {
            AegisError::ProtocolError {
                message: format!("SystemInfo Protobuf 反序列化失败: {e}"),
                code: None,
            }
        })?;
        assert!(!system_info.hostname.is_empty());
        Ok(())
    }
}
