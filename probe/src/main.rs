#![allow(missing_docs)]

#[cfg(windows)]
use std::collections::BTreeMap;
use std::fs::File;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_kw::Kek;
use common::config::{ConfigManager, load_yaml_file};
use common::crypto;
use common::governor::Governor;
use common::protocol::{
    AgentTelemetry, FileInfo, NetworkInterfaceUpdate, PayloadEnvelope, ProcessInfo, SystemInfo,
};
use common::telemetry::{init_telemetry, sample_memory_usage_mb};
use hmac::Mac;
use prost::Message;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::Oaep;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use sha2::Sha256;
#[cfg(windows)]
use wmi::WMIConnection;

use common::collectors::linux::DroppedEventCounter;

mod embedded_key {
    include!(concat!(env!("OUT_DIR"), "/embedded_org_pubkey.rs"));
}

const USER_SLOT_LEN: usize = 40;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

#[derive(Debug)]
enum EncryptorCommand {
    Payload(Vec<u8>),
    Flush,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    init_telemetry().map_err(|e| format!("初始化日志失败: {e}"))?;

    let args = parse_args(std::env::args().skip(1))?;
    let (mgr, encryptor_tx) = init_runtime(args)?;
    run_forever(&mgr, &encryptor_tx);
}

fn init_runtime(
    args: ProbeArgs,
) -> Result<(ConfigManager, mpsc::Sender<EncryptorCommand>), String> {
    let Some(config_path) = args.config_path else {
        return Err("缺少必需参数: --config <FILE>".to_string());
    };
    let mut cfg = load_yaml_file(config_path.as_path())
        .map_err(|e| format!("加载配置失败（{}）: {e}", config_path.display()))?;
    if let Some(org_key_path) = args.org_key_path {
        cfg.crypto.org_key_path = Some(org_key_path);
    }
    cfg.validate().map_err(|e| format!("配置校验失败: {e}"))?;

    validate_key_requirements(
        is_unsigned_build(),
        embedded_key::EMBEDDED_ORG_PUBKEY_DER.is_some(),
        cfg.crypto.org_key_path.is_some(),
    )?;

    let org_pubkey_der = load_org_pubkey_der(
        is_unsigned_build(),
        cfg.crypto.org_key_path.as_deref(),
        embedded_key::EMBEDDED_ORG_PUBKEY_DER,
    )?;
    tracing::info!(
        org_pubkey_bytes = org_pubkey_der.len(),
        "org public key loaded"
    );

    let org_public_key = load_rsa_public_key(org_pubkey_der.as_slice())?;
    let org_key_fp = crypto::org_pubkey_fingerprint_xxh64(org_pubkey_der.as_slice());
    let uuid_mode = if is_unsigned_build() { "dev" } else { "prod" }.to_string();
    let user_passphrase = resolve_user_passphrase(
        uuid_mode.as_str(),
        args.user_passphrase,
        cfg.crypto.user_passphrase.as_deref(),
    );
    let out_dir = config_path
        .parent()
        .map_or_else(|| PathBuf::from("."), ToOwned::to_owned);
    let encryptor_tx = spawn_encryptor(
        out_dir,
        org_public_key,
        org_key_fp,
        uuid_mode,
        user_passphrase,
    );
    enqueue_payload(
        &encryptor_tx,
        PayloadEnvelope::system_info(build_system_info()).encode_to_vec(),
    );

    let mut mgr = ConfigManager::from_config(config_path, cfg)
        .map_err(|e| format!("初始化配置管理器失败: {e}"))?;
    mgr.start_watching()
        .map_err(|e| format!("启动配置热加载失败: {e}"))?;

    Ok((mgr, encryptor_tx))
}

struct LoopState {
    last_telemetry: Instant,
    last_dropped_total: u64,
    overload_streak: u32,
    last_process_snapshot: Instant,
    last_file_snapshot: Instant,
    last_network_snapshot: Instant,
    last_ip_addresses: Vec<String>,
    last_network_update_ts: i64,
    process_exec_id_counter: std::sync::atomic::AtomicU64,
    dropped_counter: DroppedEventCounter,
    #[cfg(target_os = "linux")]
    last_bpf_snapshot: Instant,
}

impl LoopState {
    fn new() -> Self {
        Self {
            last_telemetry: Instant::now(),
            last_dropped_total: 0,
            overload_streak: 0,
            last_process_snapshot: Instant::now(),
            last_file_snapshot: Instant::now(),
            last_network_snapshot: Instant::now(),
            last_ip_addresses: collect_ip_addresses(),
            last_network_update_ts: 0,
            process_exec_id_counter: std::sync::atomic::AtomicU64::new(0),
            dropped_counter: DroppedEventCounter::default(),
            #[cfg(target_os = "linux")]
            last_bpf_snapshot: Instant::now(),
        }
    }
}

fn run_forever(mgr: &ConfigManager, encryptor_tx: &mpsc::Sender<EncryptorCommand>) -> ! {
    tracing::info!("probe started");
    let mut governor = Governor::new(mgr.current().governor.clone());
    let mut state = LoopState::new();

    loop {
        let cfg = mgr.current();
        governor.apply_config(cfg.governor.clone());
        let (cpu_usage_percent, sleep) = governor.tick_with_usage();

        maybe_emit_process_snapshot(&mut state, &mut governor, encryptor_tx);
        maybe_emit_file_snapshot(&mut state, &mut governor, cfg.as_ref(), encryptor_tx);
        maybe_emit_network_update(&mut state, &mut governor, encryptor_tx);
        maybe_emit_linux_bpf_snapshot(&mut state, &mut governor);
        maybe_emit_telemetry(
            &mut state,
            cfg.as_ref(),
            &mut governor,
            encryptor_tx,
            cpu_usage_percent,
        );

        thread::sleep(Duration::from_millis(50).saturating_add(sleep));
    }
}

fn maybe_emit_process_snapshot(
    state: &mut LoopState,
    governor: &mut Governor,
    encryptor_tx: &mpsc::Sender<EncryptorCommand>,
) {
    if state.last_process_snapshot.elapsed() < Duration::from_secs(60) {
        return;
    }
    if !governor.check_budget(1) {
        state.last_process_snapshot = Instant::now();
        return;
    }

    let processes = collect_process_snapshot(governor, &state.process_exec_id_counter, 64);
    let total = processes.len();
    let mut sent: usize = 0;
    for p in processes {
        if !governor.check_budget(1) {
            let dropped = u64::try_from(total.saturating_sub(sent)).unwrap_or(u64::MAX);
            state.dropped_counter.add(dropped);
            break;
        }
        enqueue_payload(
            encryptor_tx,
            PayloadEnvelope::process_info(p).encode_to_vec(),
        );
        sent = sent.saturating_add(1);
    }
    state.last_process_snapshot = Instant::now();
}

fn maybe_emit_file_snapshot(
    state: &mut LoopState,
    governor: &mut Governor,
    cfg: &common::config::AegisConfig,
    encryptor_tx: &mpsc::Sender<EncryptorCommand>,
) {
    if state.last_file_snapshot.elapsed() < Duration::from_secs(300) {
        return;
    }
    if !governor.check_budget(1) {
        state.last_file_snapshot = Instant::now();
        return;
    }
    if cfg.security.scan_whitelist.is_empty() {
        state.last_file_snapshot = Instant::now();
        return;
    }

    let files = collect_file_snapshot(cfg);
    let total = files.len();
    let mut sent: usize = 0;
    for f in files {
        if !governor.check_budget(1) {
            let dropped = u64::try_from(total.saturating_sub(sent)).unwrap_or(u64::MAX);
            state.dropped_counter.add(dropped);
            break;
        }
        enqueue_payload(encryptor_tx, PayloadEnvelope::file_info(f).encode_to_vec());
        sent = sent.saturating_add(1);
    }
    state.last_file_snapshot = Instant::now();
}

fn maybe_emit_network_update(
    state: &mut LoopState,
    governor: &mut Governor,
    encryptor_tx: &mpsc::Sender<EncryptorCommand>,
) {
    if state.last_network_snapshot.elapsed() < Duration::from_secs(60) {
        return;
    }
    if !governor.check_budget(1) {
        state.last_network_snapshot = Instant::now();
        return;
    }

    let ip_addresses = collect_ip_addresses();
    if ip_addresses != state.last_ip_addresses {
        let mut ts = unix_timestamp_now();
        if ts <= state.last_network_update_ts {
            ts = state.last_network_update_ts.saturating_add(1);
        }
        enqueue_payload(
            encryptor_tx,
            PayloadEnvelope::network_interface_update(NetworkInterfaceUpdate {
                timestamp: ts,
                new_ip_addresses: ip_addresses.clone(),
            })
            .encode_to_vec(),
        );
        state.last_network_update_ts = ts;
        state.last_ip_addresses = ip_addresses;
    }
    state.last_network_snapshot = Instant::now();
}

fn collect_file_snapshot(cfg: &common::config::AegisConfig) -> Vec<FileInfo> {
    #[cfg(windows)]
    {
        let mut by_drive: BTreeMap<Option<char>, Vec<String>> = BTreeMap::new();
        for p in &cfg.security.scan_whitelist {
            let drive = common::collectors::windows::drive_letter(Path::new(p));
            by_drive.entry(drive).or_default().push(p.clone());
        }

        let mut out = Vec::new();
        for (drive, paths) in by_drive {
            let snapshot = drive.and_then(|d| {
                if paths.iter().any(|p| file_should_use_vss(Path::new(p))) {
                    create_vss_snapshot_for_drive(d)
                } else {
                    None
                }
            });
            let (vss_drive, vss_device_path) = snapshot.as_ref().map_or((None, None), |s| {
                (Some(s.drive_letter), Some(s.device_path.as_str()))
            });

            let mut infos = common::collectors::windows::collect_file_infos(
                paths.as_slice(),
                cfg.security.timestomp_threshold_ms,
                vss_drive,
                vss_device_path,
            );
            out.append(&mut infos);
        }
        out
    }
    #[cfg(not(windows))]
    {
        let _ = cfg;
        Vec::new()
    }
}

#[cfg(windows)]
fn file_should_use_vss(path: &Path) -> bool {
    common::collectors::windows::is_registry_hive_path(path) || is_locked_by_share_violation(path)
}

#[cfg(windows)]
fn is_locked_by_share_violation(path: &Path) -> bool {
    let Err(err) = OpenOptions::new().read(true).open(path) else {
        return false;
    };
    matches!(err.raw_os_error(), Some(code) if code == 32 || code == 33)
}

#[cfg(windows)]
#[derive(Debug)]
struct VssSnapshot {
    drive_letter: char,
    shadow_id: String,
    device_path: String,
}

#[cfg(windows)]
impl Drop for VssSnapshot {
    fn drop(&mut self) {
        let _ignored = delete_vss_snapshot(self.shadow_id.as_str());
    }
}

#[cfg(windows)]
fn delete_vss_snapshot(shadow_id: &str) -> std::io::Result<()> {
    fn io_err(e: impl std::fmt::Display) -> std::io::Error {
        std::io::Error::other(e.to_string())
    }

    #[derive(serde::Deserialize)]
    struct Win32ShadowCopy;

    #[derive(serde::Deserialize)]
    struct DeleteOutput {
        #[serde(rename = "ReturnValue")]
        return_value: u32,
    }

    #[derive(serde::Deserialize)]
    struct ShadowCopyLookup {
        #[serde(rename = "__Path")]
        path: String,
    }

    let con = WMIConnection::new().map_err(io_err)?;

    let escaped = shadow_id.replace('\'', "''");
    let q = format!("SELECT __Path FROM Win32_ShadowCopy WHERE ID='{escaped}'");
    let rows: Vec<ShadowCopyLookup> = con.raw_query(q.as_str()).map_err(io_err)?;
    let Some(instance) = rows.first() else {
        return Ok(());
    };

    let out: DeleteOutput = con
        .exec_instance_method::<Win32ShadowCopy, _>(instance.path.as_str(), "Delete", ())
        .map_err(io_err)?;
    if out.return_value == 0 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "WMI Delete Win32_ShadowCopy failed: {}",
            out.return_value
        )))
    }
}

#[cfg(windows)]
fn create_vss_snapshot_for_drive(drive_letter: char) -> Option<VssSnapshot> {
    #[derive(serde::Deserialize)]
    struct Win32ShadowCopy;

    #[derive(serde::Serialize)]
    struct CreateInput {
        #[serde(rename = "Volume")]
        volume: String,
        #[serde(rename = "Context")]
        context: String,
    }

    #[derive(serde::Deserialize)]
    struct CreateOutput {
        #[serde(rename = "ReturnValue")]
        return_value: u32,
        #[serde(rename = "ShadowID")]
        shadow_id: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct ShadowCopyLookup {
        #[serde(rename = "__Path")]
        _path: String,
        #[serde(rename = "DeviceObject")]
        device_object: String,
    }

    let con = WMIConnection::new().ok()?;

    let volume = format!("{drive_letter}:\\");
    let input = CreateInput {
        volume,
        context: "Backup".to_string(),
    };
    let out: CreateOutput = con
        .exec_class_method::<Win32ShadowCopy, _>("Create", input)
        .ok()?;
    if out.return_value != 0 {
        return None;
    }
    let shadow_id = out.shadow_id?;

    let escaped = shadow_id.replace('\'', "''");
    let q = format!("SELECT __Path, DeviceObject FROM Win32_ShadowCopy WHERE ID='{escaped}'");
    let rows: Vec<ShadowCopyLookup> = con.raw_query(q.as_str()).ok()?;
    let instance = rows.first()?;

    Some(VssSnapshot {
        drive_letter,
        shadow_id,
        device_path: instance.device_object.clone(),
    })
}

fn maybe_emit_telemetry(
    state: &mut LoopState,
    cfg: &common::config::AegisConfig,
    governor: &mut Governor,
    encryptor_tx: &mpsc::Sender<EncryptorCommand>,
    cpu_usage_percent: u32,
) {
    let interval_sec = effective_telemetry_interval_sec(cfg);
    if state.last_telemetry.elapsed() < Duration::from_secs(interval_sec) {
        return;
    }

    let interval = state.last_telemetry.elapsed();
    let dropped_events_count = {
        let base = governor.dropped_events();
        base.saturating_add(state.dropped_counter.total())
    };

    let dropped_delta = dropped_events_count.saturating_sub(state.last_dropped_total);
    if let Some(drop_rate_percent) = compute_drop_rate_percent(
        dropped_delta,
        interval,
        cfg.governor.token_bucket.refill_per_sec,
    ) {
        if drop_rate_percent > 1 {
            state.overload_streak = state.overload_streak.saturating_add(1);
        } else {
            state.overload_streak = 0;
        }
        if state.overload_streak >= 2 {
            tracing::warn!(
                status = "Overloaded",
                drop_rate_percent,
                dropped_delta,
                interval_ms = interval.as_millis(),
                "probe overload detected"
            );
        }
    }

    let telemetry = AgentTelemetry {
        timestamp: unix_timestamp_now(),
        cpu_usage_percent,
        memory_usage_mb: sample_memory_usage_mb(),
        dropped_events_count,
    };
    tracing::info!(
        telemetry_timestamp = telemetry.timestamp,
        cpu_usage_percent = telemetry.cpu_usage_percent,
        memory_usage_mb = telemetry.memory_usage_mb,
        dropped_events_count = telemetry.dropped_events_count,
        "agent telemetry"
    );
    enqueue_payload(
        encryptor_tx,
        PayloadEnvelope::agent_telemetry(telemetry).encode_to_vec(),
    );
    if encryptor_tx.send(EncryptorCommand::Flush).is_err() {
        tracing::warn!("encryptor channel closed");
    }

    state.last_dropped_total = dropped_events_count;
    state.last_telemetry = Instant::now();
}

fn effective_telemetry_interval_sec(cfg: &common::config::AegisConfig) -> u64 {
    cfg.networking.heartbeat_interval_sec.clamp(1, 60)
}

#[cfg(target_os = "linux")]
fn collect_ip_addresses() -> Vec<String> {
    use std::collections::BTreeSet;

    let mut out: BTreeSet<String> = BTreeSet::new();

    #[allow(unsafe_code)]
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&raw mut ifap) != 0 {
            return Vec::new();
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let addr = ifa.ifa_addr;
            if !addr.is_null() {
                let family = i32::from((*addr).sa_family);
                if family == libc::AF_INET {
                    let sa = std::ptr::read_unaligned(addr.cast::<libc::sockaddr_in>());
                    insert_ipv4_if_valid(&mut out, sa.sin_addr.s_addr.to_ne_bytes());
                } else if family == libc::AF_INET6 {
                    let sa = std::ptr::read_unaligned(addr.cast::<libc::sockaddr_in6>());
                    insert_ipv6_if_valid(&mut out, sa.sin6_addr.s6_addr);
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }

    out.into_iter().collect()
}

#[cfg(target_os = "linux")]
fn insert_ipv4_if_valid(out: &mut std::collections::BTreeSet<String>, bytes: [u8; 4]) {
    let ip = std::net::Ipv4Addr::from(bytes);
    if !ip.is_loopback() && !ip.is_unspecified() {
        out.insert(ip.to_string());
    }
}

#[cfg(target_os = "linux")]
fn insert_ipv6_if_valid(out: &mut std::collections::BTreeSet<String>, bytes: [u8; 16]) {
    let ip = std::net::Ipv6Addr::from(bytes);
    if !ip.is_loopback() && !ip.is_unspecified() {
        out.insert(ip.to_string());
    }
}

#[cfg(windows)]
#[derive(serde::Deserialize)]
struct Win32NetworkAdapterConfiguration {
    #[serde(rename = "IPAddress")]
    ip_address: Option<Vec<String>>,
}

#[cfg(windows)]
fn collect_ip_addresses() -> Vec<String> {
    use std::collections::BTreeSet;

    let wmi_con = WMIConnection::new().ok();
    let Some(wmi_con) = wmi_con else {
        return Vec::new();
    };

    let query = "SELECT IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True";
    let results: Vec<Win32NetworkAdapterConfiguration> =
        wmi_con.raw_query(query).ok().unwrap_or_default();

    let mut out: BTreeSet<String> = BTreeSet::new();
    for item in results {
        let Some(addrs) = item.ip_address else {
            continue;
        };
        insert_normalized_ip_addresses(&mut out, addrs.as_slice());
    }
    out.into_iter().collect()
}

#[cfg(windows)]
fn insert_normalized_ip_addresses(out: &mut std::collections::BTreeSet<String>, addrs: &[String]) {
    for addr in addrs {
        if let Some(v) = normalize_ip_address(addr.as_str()) {
            out.insert(v);
        }
    }
}

#[cfg(windows)]
fn normalize_ip_address(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s == "127.0.0.1" || s == "::1" {
        return None;
    }
    Some(s.to_string())
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn collect_ip_addresses() -> Vec<String> {
    Vec::new()
}

fn build_system_info() -> SystemInfo {
    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    #[cfg(target_os = "linux")]
    let os_version = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            for line in s.lines() {
                let Some(rest) = line.strip_prefix("PRETTY_NAME=") else {
                    continue;
                };
                return Some(rest.trim().trim_matches('"').trim_matches('\'').to_string());
            }
            None
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string());
    #[cfg(not(target_os = "linux"))]
    let os_version = {
        #[cfg(windows)]
        {
            query_windows_os_version_wmi().unwrap_or_else(|| std::env::consts::OS.to_string())
        }
        #[cfg(not(windows))]
        {
            std::env::consts::OS.to_string()
        }
    };

    #[cfg(target_os = "linux")]
    let kernel_version = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    #[cfg(windows)]
    let kernel_version = query_windows_kernel_version_wmi().unwrap_or_default();
    #[cfg(all(not(target_os = "linux"), not(windows)))]
    let kernel_version = String::new();

    SystemInfo {
        hostname,
        os_version,
        kernel_version,
        ip_addresses: collect_ip_addresses(),
        boot_time: system_boot_time_unix().unwrap_or(0),
    }
}

#[cfg(windows)]
fn query_windows_os_version_wmi() -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Win32OperatingSystem {
        #[serde(rename = "Caption")]
        caption: String,
    }

    let wmi_con = wmi::WMIConnection::new().ok()?;
    let results: Vec<Win32OperatingSystem> = wmi_con
        .raw_query("SELECT Caption FROM Win32_OperatingSystem")
        .ok()?;
    let first = results.first()?;
    Some(first.caption.trim().to_string())
}

#[cfg(windows)]
fn query_windows_kernel_version_wmi() -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Win32OperatingSystem {
        #[serde(rename = "Version")]
        version: String,
        #[serde(rename = "BuildNumber")]
        build_number: String,
    }

    let wmi_con = wmi::WMIConnection::new().ok()?;
    let results: Vec<Win32OperatingSystem> = wmi_con
        .raw_query("SELECT Version, BuildNumber FROM Win32_OperatingSystem")
        .ok()?;
    let first = results.first()?;
    Some(format!("{} (build {})", first.version, first.build_number))
}

fn system_boot_time_unix() -> Option<i64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/uptime").ok()?;
        let first = content.split_whitespace().next()?;
        let (secs_s, frac_s) = first.split_once('.').unwrap_or((first, ""));
        let secs = secs_s.parse::<i64>().ok()?;
        let frac_first = frac_s.as_bytes().first().copied();
        let uptime_i64 = if matches!(frac_first, Some(b'5'..=b'9')) {
            secs.checked_add(1)?
        } else {
            secs
        };
        let now = unix_timestamp_now();
        Some(now.saturating_sub(uptime_i64))
    }
    #[cfg(windows)]
    {
        query_boot_time_unix_seconds_wmi()
    }
    #[cfg(all(not(target_os = "linux"), not(windows)))]
    {
        None
    }
}

#[cfg(windows)]
fn query_boot_time_unix_seconds_wmi() -> Option<i64> {
    #[derive(serde::Deserialize)]
    struct Win32OperatingSystem {
        #[serde(rename = "LastBootUpTime")]
        last_boot_up_time: String,
    }

    let wmi_con = wmi::WMIConnection::new().ok()?;
    let results: Vec<Win32OperatingSystem> = wmi_con
        .raw_query("SELECT LastBootUpTime FROM Win32_OperatingSystem")
        .ok()?;
    let first = results.first()?;
    cim_datetime_to_unix_seconds(first.last_boot_up_time.as_str())
}

#[cfg(windows)]
fn cim_datetime_to_unix_seconds(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 18 {
        return None;
    }

    let year: i32 = s.get(0..4)?.parse().ok()?;
    let month: u32 = s.get(4..6)?.parse().ok()?;
    let day: u32 = s.get(6..8)?.parse().ok()?;
    let hour: u32 = s.get(8..10)?.parse().ok()?;
    let min: u32 = s.get(10..12)?.parse().ok()?;
    let sec: u32 = s.get(12..14)?.parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }

    let mut offset_minutes: i64 = 0;
    if s.len() >= 4 {
        let tail = s.get(s.len().saturating_sub(4)..)?;
        let sign = tail.chars().next()?;
        if sign == '+' || sign == '-' {
            let mins: i64 = tail.get(1..4)?.parse().ok()?;
            offset_minutes = if sign == '+' { mins } else { -mins };
        }
    }

    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .saturating_mul(86_400)
        .saturating_add(i64::from(hour).saturating_mul(3_600))
        .saturating_add(i64::from(min).saturating_mul(60))
        .saturating_add(i64::from(sec));

    Some(seconds.saturating_sub(offset_minutes.saturating_mul(60)))
}

#[cfg(windows)]
fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1600..=9999).contains(&year) {
        return None;
    }
    if month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }

    let mut y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);

    y -= i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2).div_euclid(5) + d - 1;
    let doe = yoe * 365 + yoe.div_euclid(4) - yoe.div_euclid(100) + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn maybe_emit_linux_bpf_snapshot(state: &mut LoopState, governor: &mut Governor) {
    #[cfg(target_os = "linux")]
    {
        if state.last_bpf_snapshot.elapsed() < Duration::from_secs(300) {
            return;
        }

        let infos = match common::collectors::linux::collect_bpf_program_infos(governor, 128) {
            Ok(v) => v,
            Err(e) => {
                match &e {
                    common::AegisError::ProtocolError {
                        code: Some(code), ..
                    }
                    | common::AegisError::CryptoError {
                        code: Some(code), ..
                    } => {
                        tracing::warn!(
                            error = %e,
                            code = %code,
                            "collect bpf programs failed"
                        );
                    }
                    _ => {
                        tracing::warn!(error = %e, "collect bpf programs failed");
                    }
                }
                state.dropped_counter.add(1);
                state.last_bpf_snapshot = Instant::now();
                return;
            }
        };

        let mut high: u32 = 0;
        let mut suspicious: u32 = 0;
        let mut low: u32 = 0;
        for info in &infos {
            let h = common::collectors::linux::classify_bpf_program(info, &[]);
            match h.risk {
                common::collectors::linux::BpfRisk::HighRisk => high = high.saturating_add(1),
                common::collectors::linux::BpfRisk::Suspicious => {
                    suspicious = suspicious.saturating_add(1);
                }
                common::collectors::linux::BpfRisk::Low => low = low.saturating_add(1),
            }
        }
        tracing::info!(
            bpf_programs_total = infos.len(),
            bpf_high_risk = high,
            bpf_suspicious = suspicious,
            bpf_low = low,
            "bpf program snapshot"
        );
        state.last_bpf_snapshot = Instant::now();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, governor);
    }
}

fn collect_process_snapshot(
    governor: &mut Governor,
    exec_id_counter: &std::sync::atomic::AtomicU64,
    limit: usize,
) -> Vec<ProcessInfo> {
    #[cfg(windows)]
    {
        let _ = governor;
        common::collectors::windows::collect_process_infos(limit, exec_id_counter)
    }
    #[cfg(target_os = "linux")]
    {
        collect_process_snapshot_linux_multiview(governor, exec_id_counter, limit)
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let _ = (governor, exec_id_counter, limit);
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn collect_process_snapshot_linux_multiview(
    governor: &mut Governor,
    exec_id_counter: &std::sync::atomic::AtomicU64,
    limit: usize,
) -> Vec<ProcessInfo> {
    if limit == 0 {
        return Vec::new();
    }

    let hidden_slots = (limit / 4).max(1);
    let base_limit = limit.saturating_sub(hidden_slots);

    let mut out = common::collectors::linux::collect_process_infos(base_limit, exec_id_counter);
    let view_a = common::collectors::linux::list_proc_pids(usize::MAX);

    let mut view_b: Vec<u32> = Vec::new();
    view_b.extend(common::collectors::linux::bruteforce_proc_pids_governed(
        governor, 65_536,
    ));
    view_b.extend(common::collectors::linux::collect_cgroup_pids_governed(
        governor, 65_536, 512,
    ));
    view_b.extend(
        common::collectors::linux::collect_host_pids_via_fork_setns_governed(governor, 8, 2048),
    );
    view_b.sort_unstable();
    view_b.dedup();

    let hidden = common::collectors::linux::diff_hidden_u32(view_a.as_slice(), view_b.as_slice());
    for pid in hidden.into_iter().take(hidden_slots) {
        let mut info =
            common::collectors::linux::collect_process_info_for_pid(pid, exec_id_counter);
        info.is_ghost = true;
        out.push(info);
    }

    out
}

fn encrypt_session_key_user_slot(
    passphrase: &str,
    kdf_salt: &[u8; crypto::AES_KDF_SALT_LEN],
    session_key: &[u8; 32],
) -> Result<[u8; USER_SLOT_LEN], String> {
    let kek_bytes = crypto::derive_kek_argon2id(passphrase.as_bytes(), kdf_salt.as_slice())
        .map_err(|e| format!("Argon2id 派生 KEK 失败: {e}"))?;
    let kek = Kek::from(kek_bytes);
    let wrapped = kek
        .wrap_vec(session_key.as_slice())
        .map_err(|e| format!("AES-256-KeyWrap 加密 SessionKey 失败: {e}"))?;
    if wrapped.len() != USER_SLOT_LEN {
        return Err("AES-256-KeyWrap 输出长度异常".to_string());
    }
    let mut out = [0u8; USER_SLOT_LEN];
    let src = wrapped
        .get(..USER_SLOT_LEN)
        .ok_or_else(|| "AES-256-KeyWrap 输出长度异常".to_string())?;
    out.copy_from_slice(src);
    Ok(out)
}

#[derive(Debug)]
struct OpenArtifactSegment {
    path: PathBuf,
    file: File,
    mac: Option<HmacSha256>,
    session_key: [u8; 32],
}

impl OpenArtifactSegment {
    fn open_new(
        out_dir: &Path,
        segment_id: u64,
        org_public_key: &RsaPublicKey,
        org_key_fp: u64,
        uuid_mode: &str,
        user_passphrase: Option<&str>,
    ) -> Result<Self, String> {
        let mut kdf_salt = [0u8; crypto::AES_KDF_SALT_LEN];
        let mut rng = OsRng;
        rng.fill_bytes(&mut kdf_salt);

        let host_uuid = crypto::get_or_create_host_uuid(uuid_mode)
            .map_err(|e| format!("读取/生成 HostUUID 失败: {e}"))?;
        let header = crypto::build_aes_header_v1(&kdf_salt, &host_uuid, org_key_fp);

        let mut session_key = [0u8; 32];
        rng.fill_bytes(&mut session_key);

        let rsa_ct = org_public_key
            .encrypt(&mut rng, Oaep::new::<Sha256>(), session_key.as_slice())
            .map_err(|e| format!("RSA-OAEP 加密 SessionKey 失败: {e}"))?;

        let ts = unix_timestamp_now();
        let path = out_dir.join(format!("probe_{ts}_{segment_id}.aes"));
        let mut file = File::create(path.as_path())
            .map_err(|e| format!("创建 artifact 文件失败（{}）: {e}", path.display()))?;

        let mut mac = HmacSha256::new_from_slice(&session_key)
            .map_err(|_| "初始化 HMAC 失败（SessionKey 长度必须为 32 bytes）".to_string())?;
        mac.update(crypto::HMAC_SIG_LABEL_V1);

        file.write_all(header.as_slice())
            .map_err(|e| format!("写入 Header 失败: {e}"))?;
        mac.update(header.as_slice());

        let user_slot = user_passphrase
            .map(|p| encrypt_session_key_user_slot(p, &kdf_salt, &session_key))
            .transpose()?
            .unwrap_or([0u8; USER_SLOT_LEN]);
        file.write_all(user_slot.as_slice())
            .map_err(|e| format!("写入 UserSlot 失败: {e}"))?;
        mac.update(user_slot.as_slice());

        file.write_all(rsa_ct.as_slice())
            .map_err(|e| format!("写入 OrgSlot 失败: {e}"))?;
        mac.update(rsa_ct.as_slice());

        Ok(Self {
            path,
            file,
            mac: Some(mac),
            session_key,
        })
    }

    fn write_encrypted_chunk(&mut self, plaintext: &[u8]) -> Result<(), common::error::AegisError> {
        let encrypted = crypto::encrypt(plaintext, self.session_key.as_slice())?;
        self.file
            .write_all(encrypted.as_slice())
            .map_err(common::error::AegisError::IoError)?;
        if let Some(mac) = self.mac.as_mut() {
            mac.update(encrypted.as_slice());
        }
        Ok(())
    }

    fn finalize_and_close(mut self) -> Result<PathBuf, String> {
        let mac = self.mac.take().ok_or_else(|| "HMAC 状态缺失".to_string())?;
        let tag_bytes = mac.finalize().into_bytes();
        let tag: [u8; 32] = tag_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "HMAC 输出长度异常".to_string())?;

        let mut trailer = Vec::with_capacity(40);
        trailer.extend_from_slice(crypto::HMAC_SIG_MAGIC.as_slice());
        trailer.push(crypto::HMAC_SIG_VERSION_V1);
        trailer.push(crypto::HMAC_SIG_ALG_HMAC_SHA256);
        trailer.extend_from_slice(&[0u8; 2]);
        trailer.extend_from_slice(tag.as_slice());

        self.file
            .write_all(trailer.as_slice())
            .and_then(|()| self.file.flush())
            .map_err(|e| format!("写入 HMAC Trailer 失败: {e}"))?;

        Ok(self.path)
    }
}

fn load_rsa_public_key(der_bytes: &[u8]) -> Result<RsaPublicKey, String> {
    RsaPublicKey::from_public_key_der(der_bytes)
        .or_else(|_| RsaPublicKey::from_pkcs1_der(der_bytes))
        .map_err(|e| format!("解析 Org Public Key DER 失败: {e}"))
}

fn spawn_encryptor(
    out_dir: PathBuf,
    org_public_key: RsaPublicKey,
    org_key_fp: u64,
    uuid_mode: String,
    user_passphrase: Option<String>,
) -> mpsc::Sender<EncryptorCommand> {
    let (tx, rx) = mpsc::channel::<EncryptorCommand>();
    thread::spawn(move || {
        encryptor_loop(
            &rx,
            out_dir.as_path(),
            &org_public_key,
            org_key_fp,
            uuid_mode.as_str(),
            user_passphrase.as_deref(),
        );
    });
    tx
}

fn encryptor_loop(
    rx: &mpsc::Receiver<EncryptorCommand>,
    out_dir: &Path,
    org_public_key: &RsaPublicKey,
    org_key_fp: u64,
    uuid_mode: &str,
    user_passphrase: Option<&str>,
) {
    let mut segment_id: u64 = 0;
    let mut segment: Option<OpenArtifactSegment> = None;

    loop {
        let Ok(cmd) = rx.recv() else {
            flush_segment(&mut segment_id, &mut segment);
            break;
        };

        match cmd {
            EncryptorCommand::Payload(plaintext) => {
                if segment.is_none() {
                    match OpenArtifactSegment::open_new(
                        out_dir,
                        segment_id,
                        org_public_key,
                        org_key_fp,
                        uuid_mode,
                        user_passphrase,
                    ) {
                        Ok(mut s) => {
                            let write_system_info = PayloadEnvelope::decode(plaintext.as_slice())
                                .ok()
                                .and_then(|env| env.payload)
                                .is_none_or(|p| {
                                    !matches!(
                                        p,
                                        common::protocol::payload_envelope::Payload::SystemInfo(_)
                                    )
                                });
                            if write_system_info {
                                let system_info = PayloadEnvelope::system_info(build_system_info());
                                if s.write_encrypted_chunk(system_info.encode_to_vec().as_slice())
                                    .is_err()
                                {
                                    tracing::warn!("write system_info chunk failed");
                                    continue;
                                }
                            }
                            segment = Some(s);
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "open artifact segment failed");
                            continue;
                        }
                    }
                }

                if let Some(s) = segment.as_mut()
                    && let Err(e) = s.write_encrypted_chunk(plaintext.as_slice())
                {
                    tracing::warn!(error = %e, "encrypt/write chunk failed");
                }
            }
            EncryptorCommand::Flush => {
                flush_segment(&mut segment_id, &mut segment);
            }
        }
    }
}

fn flush_segment(segment_id: &mut u64, segment: &mut Option<OpenArtifactSegment>) {
    let Some(s) = segment.take() else {
        return;
    };

    match s.finalize_and_close() {
        Ok(path) => {
            tracing::info!(path = %path.display(), "artifact segment flushed");
            *segment_id = segment_id.saturating_add(1);
        }
        Err(e) => tracing::warn!(error = %e, "finalize artifact segment failed"),
    }
}

fn enqueue_payload(tx: &mpsc::Sender<EncryptorCommand>, bytes: Vec<u8>) {
    if tx.send(EncryptorCommand::Payload(bytes)).is_err() {
        tracing::warn!("encryptor channel closed");
    }
}

fn unix_timestamp_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs().try_into().unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

fn compute_drop_rate_percent(
    dropped_delta: u64,
    interval: Duration,
    tokens_per_sec: u32,
) -> Option<u32> {
    let interval_ms = interval.as_millis();
    if interval_ms == 0 {
        return None;
    }
    if tokens_per_sec == 0 {
        return None;
    }
    let allowed = u128::from(tokens_per_sec)
        .saturating_mul(interval_ms)
        .div_ceil(1000);
    if allowed == 0 {
        return None;
    }
    let percent = (u128::from(dropped_delta).saturating_mul(100) + (allowed / 2)) / allowed;
    let percent = percent.min(100);
    u32::try_from(percent).ok()
}

fn load_org_pubkey_der(
    is_unsigned_build: bool,
    org_key_path: Option<&std::path::Path>,
    embedded: Option<&'static [u8]>,
) -> Result<Vec<u8>, String> {
    if let Some(path) = org_key_path {
        return std::fs::read(path)
            .map_err(|e| format!("读取 org public key 失败（{}）: {e}", path.display()));
    }

    if is_unsigned_build {
        return Err("Unsigned build 模式下缺少 crypto.org_key_path".to_string());
    }

    embedded
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "缺少 org public key（外部路径与内嵌 key 均为空）".to_string())
}

fn is_unsigned_build() -> bool {
    option_env!("AEGIS_IS_UNSIGNED_BUILD").is_some()
}

fn resolve_user_passphrase(
    uuid_mode: &str,
    arg: Option<String>,
    cfg_passphrase: Option<&str>,
) -> Option<String> {
    if arg.is_some() {
        return arg;
    }
    if let Some(v) = cfg_passphrase {
        return Some(v.to_string());
    }
    match uuid_mode {
        "dev" => std::env::var("AEGIS_DEV_PASSWORD").ok(),
        _ => std::env::var("AEGIS_USER_PASSPHRASE").ok(),
    }
}

fn validate_key_requirements(
    is_unsigned_build: bool,
    has_embedded_key: bool,
    has_external_key_path: bool,
) -> Result<(), String> {
    if is_unsigned_build {
        if !has_external_key_path {
            return Err(
                "Unsigned build 模式下必须显式配置 crypto.org_key_path 或传入 --org-key-path"
                    .to_string(),
            );
        }
        return Ok(());
    }

    if !has_external_key_path && !has_embedded_key {
        return Err(
            "必须显式配置 crypto.org_key_path 或在构建期注入 AEGIS_ORG_PUBKEY_PATH".to_string(),
        );
    }
    Ok(())
}

#[derive(Debug)]
struct ProbeArgs {
    config_path: Option<PathBuf>,
    org_key_path: Option<PathBuf>,
    user_passphrase: Option<String>,
}

fn parse_args<I>(mut it: I) -> Result<ProbeArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut config_path: Option<PathBuf> = None;
    let mut org_key_path: Option<PathBuf> = None;
    let mut user_passphrase: Option<String> = None;

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => {
                let val = it.next().ok_or("--config 缺少参数".to_string())?;
                config_path = Some(PathBuf::from(val));
            }
            "--org-key-path" => {
                let val = it.next().ok_or("--org-key-path 缺少参数".to_string())?;
                org_key_path = Some(PathBuf::from(val));
            }
            "--user-passphrase" | "--password" => {
                let val = it
                    .next()
                    .ok_or("--user-passphrase/--password 缺少参数".to_string())?;
                user_passphrase = Some(val);
            }
            "--help" | "-h" => {
                return Err(
                    "Usage: probe --config <FILE> [--org-key-path <FILE>] [--user-passphrase <TEXT>]\n"
                        .to_string(),
                );
            }
            other => return Err(format!("未知参数: {other}")),
        }
    }

    Ok(ProbeArgs {
        config_path,
        org_key_path,
        user_passphrase,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::cim_datetime_to_unix_seconds;
    use super::{
        OpenArtifactSegment, USER_SLOT_LEN, compute_drop_rate_percent,
        effective_telemetry_interval_sec, validate_key_requirements,
    };
    use common::crypto;
    use common::protocol::{PayloadEnvelope, payload_envelope};
    use prost::Message;
    use rand::rngs::OsRng;
    use rsa::Oaep;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::traits::PublicKeyParts;
    use sha2::Sha256;
    use std::time::Duration;

    #[test]
    fn unsigned_build_requires_external_key_path() {
        assert!(validate_key_requirements(true, false, false).is_err());
        assert!(validate_key_requirements(true, true, false).is_err());
        assert!(validate_key_requirements(true, false, true).is_ok());
        assert!(validate_key_requirements(true, true, true).is_ok());
    }

    #[test]
    fn telemetry_interval_is_capped_at_60s() {
        let mut cfg = common::config::AegisConfig::default();
        cfg.networking.heartbeat_interval_sec = 60;
        assert_eq!(effective_telemetry_interval_sec(&cfg), 60);

        cfg.networking.heartbeat_interval_sec = 10;
        assert_eq!(effective_telemetry_interval_sec(&cfg), 10);

        cfg.networking.heartbeat_interval_sec = 300;
        assert_eq!(effective_telemetry_interval_sec(&cfg), 60);
    }

    #[test]
    fn signed_build_requires_embedded_or_external_key() {
        assert!(validate_key_requirements(false, false, false).is_err());
        assert!(validate_key_requirements(false, true, false).is_ok());
        assert!(validate_key_requirements(false, false, true).is_ok());
        assert!(validate_key_requirements(false, true, true).is_ok());
    }

    #[test]
    fn drop_rate_percent_is_none_for_invalid_inputs() {
        assert_eq!(
            compute_drop_rate_percent(1, Duration::from_secs(0), 10_000),
            None
        );
        assert_eq!(
            compute_drop_rate_percent(1, Duration::from_secs(60), 0),
            None
        );
    }

    #[test]
    fn drop_rate_percent_tracks_over_one_percent() {
        let interval = Duration::from_secs(60);
        let tokens_per_sec = 10_000;
        assert_eq!(
            compute_drop_rate_percent(6_000, interval, tokens_per_sec),
            Some(1)
        );
        assert_eq!(
            compute_drop_rate_percent(12_000, interval, tokens_per_sec),
            Some(2)
        );
        assert_eq!(
            compute_drop_rate_percent(0, interval, tokens_per_sec),
            Some(0)
        );
    }

    #[cfg(windows)]
    #[test]
    fn cim_datetime_epoch_converts_to_unix_zero() {
        assert_eq!(
            cim_datetime_to_unix_seconds("19700101000000.000000+000"),
            Some(0)
        );
    }

    #[cfg(windows)]
    #[test]
    fn cim_datetime_with_negative_timezone_offsets_to_utc() {
        assert_eq!(
            cim_datetime_to_unix_seconds("19700101000000.000000-480"),
            Some(28_800)
        );
    }

    fn decrypt_stream_to_plaintexts(
        stream: &[u8],
        session_key: &[u8; 32],
        max_items: usize,
    ) -> Result<Vec<Vec<u8>>, common::error::AegisError> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut offset: usize = 0;
        for _ in 0..max_items {
            if offset + 28 > stream.len() {
                break;
            }
            let payload_len = u32::from_be_bytes([
                stream[offset + 24],
                stream[offset + 25],
                stream[offset + 26],
                stream[offset + 27],
            ]) as usize;
            let chunk_len = 24usize + 4 + payload_len + 16;
            let Some(end) = offset.checked_add(chunk_len) else {
                break;
            };
            let Some(chunk) = stream.get(offset..end) else {
                break;
            };
            offset = end;
            out.push(crypto::decrypt(chunk, session_key.as_slice())?);
        }
        Ok(out)
    }

    #[test]
    fn probe_artifact_segment_roundtrip_matches_doc06_layout() -> Result<(), String> {
        let mut rng = OsRng;
        let private_key =
            RsaPrivateKey::new(&mut rng, 2048).map_err(|e| format!("生成 RSA 私钥失败: {e}"))?;
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| format!("导出 Org Public Key DER 失败: {e}"))?
            .as_bytes()
            .to_vec();
        let org_key_fp = crypto::org_pubkey_fingerprint_xxh64(public_key_der.as_slice());

        let dir = std::env::temp_dir().join(format!(
            "aegis_probe_test_{}_{}",
            std::process::id(),
            crypto::org_pubkey_fingerprint_xxh64(public_key_der.as_slice())
        ));
        std::fs::create_dir_all(dir.as_path())
            .map_err(|e| format!("创建临时目录失败（{}）: {e}", dir.display()))?;

        let mut seg = OpenArtifactSegment::open_new(
            dir.as_path(),
            0,
            &public_key,
            org_key_fp,
            "dev",
            Some("aegis-dev"),
        )?;
        let env = PayloadEnvelope::system_info(common::protocol::SystemInfo {
            hostname: "h".to_string(),
            os_version: "o".to_string(),
            kernel_version: "k".to_string(),
            ip_addresses: Vec::new(),
            boot_time: 1,
        });
        seg.write_encrypted_chunk(env.encode_to_vec().as_slice())
            .map_err(|e| format!("写入 payload 失败: {e}"))?;
        let path = seg.finalize_and_close()?;

        let bytes = std::fs::read(path.as_path())
            .map_err(|e| format!("读取 artifact 文件失败（{}）: {e}", path.display()))?;
        let rsa_ct_len = private_key.size();
        if bytes.len() < crypto::AES_HEADER_LEN + USER_SLOT_LEN + rsa_ct_len + 40 {
            return Err("Artifact 长度不足".to_string());
        }
        if bytes.get(..crypto::AES_MAGIC.len()) != Some(crypto::AES_MAGIC.as_slice()) {
            return Err("Artifact magic 不匹配".to_string());
        }

        let user_slot_start = crypto::AES_HEADER_LEN;
        let user_slot_end = user_slot_start + USER_SLOT_LEN;
        let user_slot = bytes
            .get(user_slot_start..user_slot_end)
            .ok_or("读取 UserSlot 失败".to_string())?;
        if user_slot.iter().all(|b| *b == 0) {
            return Err("UserSlot 不应为全零".to_string());
        }

        let rsa_start = user_slot_end;
        let rsa_end = rsa_start + rsa_ct_len;
        let rsa_ct = bytes
            .get(rsa_start..rsa_end)
            .ok_or("读取 OrgSlot 失败".to_string())?;
        let stream = bytes.get(rsa_end..).ok_or("读取 stream 失败".to_string())?;

        let kdf_salt: [u8; crypto::AES_KDF_SALT_LEN] = bytes
            [crypto::AES_KDF_SALT_OFFSET..crypto::AES_KDF_SALT_OFFSET + crypto::AES_KDF_SALT_LEN]
            .try_into()
            .map_err(|_| "读取 KDF_Salt 失败".to_string())?;
        let kek_bytes = crypto::derive_kek_argon2id("aegis-dev".as_bytes(), kdf_salt.as_ref())
            .map_err(|e| format!("派生 KEK 失败: {e}"))?;
        let kek = aes_kw::Kek::from(kek_bytes);
        let unwrapped = kek
            .unwrap_vec(user_slot)
            .map_err(|e| format!("解开 UserSlot 失败: {e}"))?;
        let session_key_from_user: [u8; 32] = unwrapped
            .as_slice()
            .try_into()
            .map_err(|_| "UserSlot 解出的 SessionKey 长度异常".to_string())?;

        let session_key_bytes = private_key
            .decrypt(Oaep::new::<Sha256>(), rsa_ct)
            .map_err(|e| format!("RSA-OAEP 解密 SessionKey 失败: {e}"))?;
        let session_key_from_org: [u8; 32] = session_key_bytes
            .try_into()
            .map_err(|_| "OrgSlot 解出的 SessionKey 长度异常".to_string())?;
        if session_key_from_org != session_key_from_user {
            return Err("UserSlot 与 OrgSlot 解出的 SessionKey 不一致".to_string());
        }

        let verify = crypto::verify_hmac_sig_trailer_v1(bytes.as_slice(), &session_key_from_org)
            .map_err(|e| format!("HMAC trailer 验证失败: {e}"))?;
        if verify != crypto::HmacSigVerification::Valid {
            return Err("HMAC trailer 校验未通过".to_string());
        }

        let plaintexts = decrypt_stream_to_plaintexts(stream, &session_key_from_org, 16)
            .map_err(|e| format!("解密 stream 失败: {e}"))?;
        let first = plaintexts.first().ok_or("缺少第一个 chunk".to_string())?;
        let env = PayloadEnvelope::decode(first.as_slice())
            .map_err(|e| format!("PayloadEnvelope 反序列化失败: {e}"))?;
        match env.payload {
            Some(payload_envelope::Payload::SystemInfo(_)) => Ok(()),
            _ => Err("第一个 chunk 必须是 SystemInfo".to_string()),
        }
    }
}
