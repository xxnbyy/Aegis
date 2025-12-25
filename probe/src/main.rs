#![allow(missing_docs)]

#[cfg(windows)]
use std::collections::BTreeMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_kw::Kek;
use base64::Engine as _;
use common::config::{ArtifactConfig, ConfigManager, load_yaml_file};
use common::crypto;
use common::detection::{RuleManager, RuleSet};
use common::governor::{Governor, IoLimiter};
#[cfg(windows)]
use common::protocol::EvidenceChunker;
use common::protocol::{
    AgentTelemetry, FileInfo, NetworkInterfaceUpdate, PayloadEnvelope, ProcessInfo,
    SmartReflexEvidence, SystemInfo, payload_envelope,
};
#[cfg(target_os = "linux")]
use common::protocol::{EbpfEvent, EbpfEventBatch, LinuxKernelForensicsEvidence, LinuxVdsoHash};
use common::telemetry::{init_telemetry, sample_memory_usage_mb};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use hmac::Mac;
use libloading::Library;
use prost::Message;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::Oaep;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey as RsaPkcs1v15SigningKey;
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaPkcs1v15VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::signature::Verifier;
use serde::Deserialize;
use sha2::Digest as _;
use sha2::Sha256;
use std::collections::HashSet;
use tokio::sync::mpsc as tokio_mpsc;
use wasmtime::{Caller, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
#[cfg(windows)]
use wmi::WMIConnection;

use common::collectors::linux::DroppedEventCounter;

mod embedded_key {
    include!(concat!(env!("OUT_DIR"), "/embedded_org_pubkey.rs"));
}

mod embedded_self_ed25519 {
    include!(concat!(env!("OUT_DIR"), "/embedded_self_ed25519_pubkey.rs"));
}

const USER_SLOT_LEN: usize = 40;
const WASM_PLUGIN_ABI_VERSION: i32 = 1;
const NATIVE_PLUGIN_ABI_VERSION: u32 = 1;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type EventBusTx = tokio_mpsc::UnboundedSender<EncryptorCommand>;
type EventBusRx = tokio_mpsc::UnboundedReceiver<EncryptorCommand>;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct WasmManifest {
    permissions: Vec<String>,
}

struct PluginManager {
    wasm: Option<WasmRuntime>,
    native: Vec<NativePluginHandle>,
}

struct WasmRuntime {
    engine: Engine,
    plugins: Vec<WasmPlugin>,
}

#[derive(Clone)]
struct WasmHostState {
    permissions: HashSet<String>,
    limits: StoreLimits,
}

struct WasmPlugin {
    name: String,
    module_path: PathBuf,
    permissions: Vec<String>,
    module: Module,
}

type NativeInit = unsafe extern "C" fn() -> i32;
type NativeAbiVersion = unsafe extern "C" fn() -> u32;
type NativeExecute = unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize) -> i32;
type NativeFree = unsafe extern "C" fn(*mut u8, usize);
type NativeShutdown = unsafe extern "C" fn();

struct NativePlugin {
    name: String,
    path: PathBuf,
    execute: NativeExecute,
    free: NativeFree,
    shutdown: Option<NativeShutdown>,
    _library: Library,
}

enum NativePluginHandle {
    InProcess(NativePlugin),
    Subprocess(SubprocessNativePlugin),
}

struct SubprocessNativePlugin {
    name: String,
    path: PathBuf,
    org_pubkey_der_b64: String,
    timeout_ms: u64,
    sig_mode: String,
}

fn run_native_plugin_worker(args: NativePluginWorkerArgs) -> Result<(), String> {
    use std::io::Read;

    let org_pubkey_der = base64::engine::general_purpose::STANDARD
        .decode(args.org_pubkey_der_b64.as_bytes())
        .map_err(|e| format!("org_pubkey_der_b64 base64 解码失败: {e}"))?;
    let org_public_key = load_rsa_public_key(org_pubkey_der.as_slice())?;
    verify_native_plugin_sig(
        args.sig_mode.as_str(),
        &org_public_key,
        args.plugin_path.as_path(),
    )?;

    let name = args
        .plugin_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("native_plugin")
        .to_string();
    let plugin = load_native_plugin_in_process(args.plugin_path, name)?;

    let mut stdin_text = String::new();
    std::io::stdin()
        .read_to_string(&mut stdin_text)
        .map_err(|e| format!("读取 stdin 失败: {e}"))?;
    let input_b64 = stdin_text.lines().find(|l| !l.trim().is_empty());
    let Some(input_b64) = input_b64 else {
        return Ok(());
    };
    let input = base64::engine::general_purpose::STANDARD
        .decode(input_b64.trim().as_bytes())
        .map_err(|e| format!("stdin base64 解码失败: {e}"))?;

    let out = plugin.execute(input.as_slice())?;
    if let Some(bytes) = out {
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes.as_slice());
        println!("{b64}");
    }
    Ok(())
}

impl PluginManager {
    fn load(
        base_dir: &Path,
        security: &common::config::SecurityConfig,
        org_public_key: &RsaPublicKey,
        org_pubkey_der: &[u8],
    ) -> Result<Self, String> {
        let wasm = if security.wasm_plugin_paths.is_empty() {
            None
        } else {
            Some(load_wasm_runtime(base_dir, security)?)
        };

        let native = if security.native_plugin_paths.is_empty() {
            Vec::new()
        } else {
            if !security.enable_native_plugins {
                return Err(
                    "security.enable_native_plugins=false 时不允许加载 native_plugin_paths"
                        .to_string(),
                );
            }
            load_native_plugins(base_dir, security, org_public_key, org_pubkey_der)?
        };

        Ok(Self { wasm, native })
    }

    fn wasm_count(&self) -> usize {
        self.wasm.as_ref().map_or(0, |r| r.plugins.len())
    }

    fn native_count(&self) -> usize {
        self.native.len()
    }

    fn wasm_plugin_names(&self) -> Vec<String> {
        self.wasm.as_ref().map_or_else(Vec::new, |r| {
            r.plugins.iter().map(|p| p.name.clone()).collect()
        })
    }

    fn native_plugin_names(&self) -> Vec<String> {
        self.native
            .iter()
            .map(|p| match p {
                NativePluginHandle::InProcess(p) => p.name.clone(),
                NativePluginHandle::Subprocess(p) => p.name.clone(),
            })
            .collect()
    }

    fn wasm_plugin_entries(&self) -> Vec<(String, String, usize)> {
        self.wasm.as_ref().map_or_else(Vec::new, |r| {
            r.plugins
                .iter()
                .map(|p| {
                    (
                        p.name.clone(),
                        p.module_path.display().to_string(),
                        p.permissions.len(),
                    )
                })
                .collect()
        })
    }

    fn native_plugin_entries(&self) -> Vec<(String, String)> {
        self.native
            .iter()
            .map(|p| match p {
                NativePluginHandle::InProcess(p) => (p.name.clone(), p.path.display().to_string()),
                NativePluginHandle::Subprocess(p) => (p.name.clone(), p.path.display().to_string()),
            })
            .collect()
    }

    fn execute_governed(&self, governor: &mut Governor, input: &[u8]) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();

        if let Some(wasm) = self.wasm.as_ref() {
            match wasm.execute_governed(governor, input) {
                Ok(mut v) => out.append(&mut v),
                Err(e) => tracing::warn!(error = e, "wasm plugin execute failed"),
            }
        }

        for p in &self.native {
            if !governor.try_consume_budget(1) {
                break;
            }
            match p.execute(input) {
                Ok(Some(bytes)) => out.push(bytes),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = e, "native plugin execute failed"),
            }
        }

        out
    }
}

impl NativePluginHandle {
    fn execute(&self, input: &[u8]) -> Result<Option<Vec<u8>>, String> {
        match self {
            Self::InProcess(p) => p.execute(input),
            Self::Subprocess(p) => p.execute(input),
        }
    }
}

impl SubprocessNativePlugin {
    #[allow(clippy::too_many_lines)]
    fn execute(&self, input: &[u8]) -> Result<Option<Vec<u8>>, String> {
        use std::io::Read;
        use std::io::Write;
        use std::process::Command;
        use std::process::Stdio;
        use std::sync::mpsc;

        const MAX_INPUT: usize = 1024 * 1024;
        const MAX_OUTPUT: usize = 1024 * 1024;
        if input.len() > MAX_INPUT {
            return Err(format!(
                "native input bytes 超限: {} > {}",
                input.len(),
                MAX_INPUT
            ));
        }

        let exe = std::env::current_exe().map_err(|e| format!("定位当前可执行文件失败: {e}"))?;
        let mut cmd = Command::new(exe);
        cmd.arg("--native-plugin-worker")
            .arg("--plugin")
            .arg(self.path.as_os_str())
            .arg("--org-pubkey-der-b64")
            .arg(self.org_pubkey_der_b64.as_str())
            .arg("--sig-mode")
            .arg(self.sig_mode.as_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        apply_native_plugin_worker_hardening(&mut cmd);

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("启动 native 插件子进程失败: {e}"))?;

        #[cfg(windows)]
        let _job_guard = apply_native_plugin_worker_sandbox_best_effort(&child)?;
        #[cfg(not(windows))]
        apply_native_plugin_worker_sandbox_best_effort(&child);

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| "native 子进程 stdin 不可用".to_string())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "native 子进程 stdout 不可用".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "native 子进程 stderr 不可用".to_string())?;

        let input_b64 = base64::engine::general_purpose::STANDARD.encode(input);
        stdin
            .write_all(format!("{input_b64}\n").as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("写入 native 子进程 stdin 失败: {e}"))?;
        drop(stdin);

        let (stdout_tx, stdout_rx) = mpsc::channel::<Vec<u8>>();
        let (stderr_tx, stderr_rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            drop(std::io::BufReader::new(stdout).read_to_end(&mut buf));
            drop(stdout_tx.send(buf));
        });
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            drop(std::io::BufReader::new(stderr).read_to_end(&mut buf));
            drop(stderr_tx.send(buf));
        });

        let timeout = Duration::from_millis(self.timeout_ms);
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| format!("等待 native 子进程失败: {e}"))?
            {
                break status;
            }
            if start.elapsed() > timeout {
                drop(child.kill());
                drop(child.wait());
                return Err(format!(
                    "native 子进程执行超时: {}ms (plugin={})",
                    self.timeout_ms,
                    self.path.display()
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        let stdout_bytes = stdout_rx.recv().unwrap_or_default();
        let stderr_bytes = stderr_rx.recv().unwrap_or_default();

        if !status.success() {
            let stderr = String::from_utf8_lossy(stderr_bytes.as_slice()).to_string();
            return Err(format!(
                "native 子进程执行失败: status={status} stderr={stderr}"
            ));
        }

        let stdout_text = String::from_utf8_lossy(stdout_bytes.as_slice());
        let trimmed = stdout_text.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let out = base64::engine::general_purpose::STANDARD
            .decode(trimmed.as_bytes())
            .map_err(|e| format!("native 子进程 stdout base64 解码失败: {e}"))?;
        if out.len() > MAX_OUTPUT {
            return Err(format!(
                "native output bytes 超限: {} > {}",
                out.len(),
                MAX_OUTPUT
            ));
        }
        Ok(Some(out))
    }
}

fn apply_native_plugin_worker_hardening(cmd: &mut std::process::Command) {
    cmd.current_dir(std::env::temp_dir());
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let self_key = std::env::var_os("AEGIS_SELF_ED25519_PUBKEY_PATH");
        cmd.env_clear();
        if let Some(v) = self_key {
            cmd.env("AEGIS_SELF_ED25519_PUBKEY_PATH", v);
        }
        #[allow(unsafe_code)]
        unsafe {
            cmd.pre_exec(|| {
                let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let _ = libc::setrlimit(libc::RLIMIT_CORE, &raw const core);
                let nofile = libc::rlimit {
                    rlim_cur: 128,
                    rlim_max: 128,
                };
                let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &raw const nofile);
                Ok(())
            });
        }
    }
}

#[cfg(windows)]
struct NativePluginJobGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for NativePluginJobGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn apply_native_plugin_worker_sandbox_best_effort(
    child: &std::process::Child,
) -> Result<NativePluginJobGuard, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    let job: HANDLE = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job == 0 {
        return Err(format!(
            "CreateJobObjectW 失败: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw mut info).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                .unwrap_or(u32::MAX),
        )
    };
    if ok == 0 {
        unsafe {
            let _ = CloseHandle(job);
        }
        return Err(format!(
            "SetInformationJobObject 失败: {}",
            std::io::Error::last_os_error()
        ));
    }

    let child_handle = child.as_raw_handle() as HANDLE;
    let ok = unsafe { AssignProcessToJobObject(job, child_handle) };
    if ok == 0 {
        unsafe {
            let _ = CloseHandle(job);
        }
        return Err(format!(
            "AssignProcessToJobObject 失败: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(NativePluginJobGuard(job))
}

#[cfg(not(windows))]
fn apply_native_plugin_worker_sandbox_best_effort(_child: &std::process::Child) {}

fn resolve_config_relative_path(base_dir: &Path, raw: &str) -> PathBuf {
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        return p;
    }
    base_dir.join(p)
}

fn load_wasm_runtime(
    base_dir: &Path,
    security: &common::config::SecurityConfig,
) -> Result<WasmRuntime, String> {
    let mut cfg = wasmtime::Config::new();
    cfg.consume_fuel(true);
    let engine = Engine::new(&cfg).map_err(|e| format!("初始化 Wasm engine 失败: {e}"))?;

    let allow: HashSet<&str> = security
        .wasm_permissions_allow
        .iter()
        .map(String::as_str)
        .collect();

    let mut plugins: Vec<WasmPlugin> = Vec::new();
    for raw_path in &security.wasm_plugin_paths {
        let module_path = resolve_config_relative_path(base_dir, raw_path.as_str());
        let manifest_path = module_path
            .parent()
            .ok_or_else(|| format!("Wasm 插件路径缺少 parent: {}", module_path.display()))?
            .join("manifest.json");
        let manifest_text = std::fs::read_to_string(manifest_path.as_path()).map_err(|e| {
            format!(
                "读取 Wasm manifest 失败（{}）: {e}",
                manifest_path.display()
            )
        })?;
        let manifest: WasmManifest = serde_json::from_str(manifest_text.as_str()).map_err(|e| {
            format!(
                "解析 Wasm manifest 失败（{}）: {e}",
                manifest_path.display()
            )
        })?;

        if allow.is_empty() && !manifest.permissions.is_empty() {
            return Err(format!(
                "Wasm 插件权限未配置 allowlist，但插件声明了 permissions: {}",
                module_path.display()
            ));
        }

        for perm in &manifest.permissions {
            if !allow.contains(perm.as_str()) {
                return Err(format!(
                    "Wasm 插件权限不被允许: perm={perm}, plugin={}",
                    module_path.display()
                ));
            }
        }

        let module = Module::from_file(&engine, module_path.as_path())
            .map_err(|e| format!("加载 Wasm module 失败（{}）: {e}", module_path.display()))?;

        let perms: HashSet<String> = manifest.permissions.iter().cloned().collect();
        let linker = build_wasm_linker(&engine, &perms)?;
        let mut store = Store::new(
            &engine,
            WasmHostState {
                permissions: perms.clone(),
                limits: default_wasm_store_limits(),
            },
        );
        store.limiter(|s| &mut s.limits);
        store
            .set_fuel(10_000_000)
            .map_err(|e| format!("Wasm set_fuel 失败（{}）: {e}", module_path.display()))?;
        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| format!("Wasm instantiate 失败（{}）: {e}", module_path.display()))?;
        validate_wasm_plugin_instance(&mut store, &instance, module_path.as_path())?;

        let name = module_path
            .parent()
            .and_then(|p| p.file_name())
            .or_else(|| module_path.file_stem())
            .and_then(|s| s.to_str())
            .unwrap_or("wasm_plugin")
            .to_string();

        plugins.push(WasmPlugin {
            name,
            module_path,
            permissions: manifest.permissions,
            module,
        });
    }

    Ok(WasmRuntime { engine, plugins })
}

fn default_wasm_store_limits() -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(64 * 1024 * 1024)
        .table_elements(20_000)
        .build()
}

fn validate_wasm_plugin_instance(
    store: &mut Store<WasmHostState>,
    instance: &wasmtime::Instance,
    module_path: &Path,
) -> Result<(), String> {
    if instance
        .get_func(&mut *store, "aegis_abi_version")
        .is_some()
    {
        let abi = instance
            .get_typed_func::<(), i32>(&mut *store, "aegis_abi_version")
            .map_err(|e| {
                format!(
                    "Wasm 插件导出 aegis_abi_version 签名不匹配（{}）: {e}",
                    module_path.display()
                )
            })?;
        let v = abi.call(&mut *store, ()).map_err(|e| {
            format!(
                "Wasm 调用 aegis_abi_version 失败（{}）: {e}",
                module_path.display()
            )
        })?;
        if v != WASM_PLUGIN_ABI_VERSION {
            return Err(format!(
                "Wasm 插件 ABI version 不匹配（{}）: plugin={v}, expected={WASM_PLUGIN_ABI_VERSION}",
                module_path.display()
            ));
        }
    }

    instance
        .get_memory(&mut *store, "memory")
        .ok_or_else(|| format!("Wasm 插件缺少导出 memory（{}）", module_path.display()))?;

    instance
        .get_typed_func::<i32, i32>(&mut *store, "aegis_alloc")
        .map_err(|e| {
            format!(
                "Wasm 插件缺少导出 aegis_alloc（{}）: {e}",
                module_path.display()
            )
        })?;

    instance
        .get_typed_func::<(i32, i32), i64>(&mut *store, "aegis_execute")
        .map_err(|e| {
            format!(
                "Wasm 插件缺少导出 aegis_execute（{}）: {e}",
                module_path.display()
            )
        })?;

    Ok(())
}

impl WasmRuntime {
    fn execute_governed(
        &self,
        governor: &mut Governor,
        input: &[u8],
    ) -> Result<Vec<Vec<u8>>, String> {
        const MAX_INPUT: usize = 256 * 1024;
        if input.len() > MAX_INPUT {
            return Err(format!(
                "wasm input bytes 超限: {} > {}",
                input.len(),
                MAX_INPUT
            ));
        }

        let mut out: Vec<Vec<u8>> = Vec::new();
        for p in &self.plugins {
            if !governor.try_consume_budget(1) {
                break;
            }
            if let Some(bytes) = execute_single_wasm_plugin(&self.engine, governor, p, input)? {
                out.push(bytes);
            }
        }

        Ok(out)
    }
}

fn execute_single_wasm_plugin(
    engine: &Engine,
    governor: &mut Governor,
    plugin: &WasmPlugin,
    input: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    const MAX_OUTPUT: usize = 256 * 1024;
    const FUEL_PER_EXEC: u64 = 50_000_000;

    if !governor.try_consume_budget(1) {
        return Ok(None);
    }

    let perms: HashSet<String> = plugin.permissions.iter().cloned().collect();
    let linker = build_wasm_linker(engine, &perms)?;
    let mut store = Store::new(
        engine,
        WasmHostState {
            permissions: perms,
            limits: default_wasm_store_limits(),
        },
    );
    store.limiter(|s| &mut s.limits);
    store.set_fuel(FUEL_PER_EXEC).map_err(|e| {
        format!(
            "Wasm set_fuel 失败（{}）: {e}",
            plugin.module_path.display()
        )
    })?;
    let instance = linker
        .instantiate(&mut store, &plugin.module)
        .map_err(|e| {
            format!(
                "Wasm instantiate 失败（{}）: {e}",
                plugin.module_path.display()
            )
        })?;
    validate_wasm_plugin_instance(&mut store, &instance, plugin.module_path.as_path())?;

    let mem = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| format!("Wasm 插件缺少 memory（{}）", plugin.module_path.display()))?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&mut store, "aegis_alloc")
        .map_err(|e| {
            format!(
                "Wasm 获取 aegis_alloc 失败（{}）: {e}",
                plugin.module_path.display()
            )
        })?;
    let exec = instance
        .get_typed_func::<(i32, i32), i64>(&mut store, "aegis_execute")
        .map_err(|e| {
            format!(
                "Wasm 获取 aegis_execute 失败（{}）: {e}",
                plugin.module_path.display()
            )
        })?;
    let free = instance
        .get_typed_func::<(i32, i32), ()>(&mut store, "aegis_free")
        .ok();

    let input_len = i32::try_from(input.len()).unwrap_or(i32::MAX);
    let ptr = alloc.call(&mut store, input_len).map_err(|e| {
        format!(
            "Wasm aegis_alloc call 失败（{}）: {e}",
            plugin.module_path.display()
        )
    })?;
    let ptr_usize = usize::try_from(ptr).map_err(|_| "Wasm 返回 ptr 非法".to_string())?;
    mem.write(&mut store, ptr_usize, input).map_err(|e| {
        format!(
            "Wasm 写入 input 失败（{}）: {e}",
            plugin.module_path.display()
        )
    })?;

    let raw = exec.call(&mut store, (ptr, input_len)).map_err(|e| {
        format!(
            "Wasm aegis_execute call 失败（{}）: {e}",
            plugin.module_path.display()
        )
    })?;
    let (out_ptr, out_len) = decode_wasm_ptr_len(raw)
        .ok_or_else(|| format!("Wasm 返回值无效（{}）: {raw}", plugin.module_path.display()))?;
    if out_ptr == 0 || out_len == 0 {
        return Ok(None);
    }

    let out_len_usize = usize::try_from(out_len).map_err(|_| "Wasm out_len 非法".to_string())?;
    if out_len_usize > MAX_OUTPUT {
        return Err(format!(
            "wasm output bytes 超限: {out_len_usize} > {MAX_OUTPUT}"
        ));
    }

    let out_ptr_usize = usize::try_from(out_ptr).map_err(|_| "Wasm out_ptr 非法".to_string())?;
    let mut buf = vec![0u8; out_len_usize];
    mem.read(&store, out_ptr_usize, buf.as_mut_slice())
        .map_err(|e| {
            format!(
                "Wasm 读取 output 失败（{}）: {e}",
                plugin.module_path.display()
            )
        })?;

    if let Some(free) = free
        && let Err(e) = free.call(&mut store, (out_ptr, out_len))
    {
        tracing::warn!(error = %e, "Wasm aegis_free failed");
    }

    Ok(Some(buf))
}

fn decode_wasm_ptr_len(v: i64) -> Option<(i32, i32)> {
    if v == 0 {
        return Some((0, 0));
    }
    if v < 0 {
        return None;
    }
    let raw = u64::try_from(v).ok()?;
    let ptr = (raw & 0xffff_ffff) as u32;
    let len = (raw >> 32) as u32;
    Some((i32::try_from(ptr).ok()?, i32::try_from(len).ok()?))
}

fn build_wasm_linker(
    engine: &Engine,
    permissions: &HashSet<String>,
) -> Result<Linker<WasmHostState>, String> {
    let mut linker = Linker::<WasmHostState>::new(engine);

    add_wasm_host_now_ms(&mut linker)?;

    if permissions.contains("fs_read_logs") {
        add_wasm_host_fs_read_logs(&mut linker)?;
    }

    if permissions.contains("net_connect_virustotal") {
        add_wasm_host_net_connect_virustotal(&mut linker)?;
    }

    Ok(linker)
}

fn add_wasm_host_now_ms(linker: &mut Linker<WasmHostState>) -> Result<(), String> {
    linker
        .func_wrap("aegis", "now_ms", |_: Caller<'_, WasmHostState>| -> i64 {
            let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) else {
                return 0;
            };
            i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
        })
        .map_err(|e| format!("注册 host function aegis.now_ms 失败: {e}"))?;
    Ok(())
}

fn add_wasm_host_fs_read_logs(linker: &mut Linker<WasmHostState>) -> Result<(), String> {
    linker
        .func_wrap(
            "aegis",
            "fs_read_logs",
            |mut caller: Caller<'_, WasmHostState>,
             path_ptr: i32,
             path_len: i32,
             out_ptr: i32,
             out_len: i32|
             -> i32 {
                if !caller.data().permissions.contains("fs_read_logs") {
                    return -3;
                }

                let Some(mem) = caller
                    .get_export("memory")
                    .and_then(wasmtime::Extern::into_memory)
                else {
                    return -1;
                };

                let Ok(path_usize) = usize::try_from(path_ptr) else {
                    return -2;
                };
                let Ok(path_len_usize) = usize::try_from(path_len) else {
                    return -2;
                };
                let Ok(out_usize) = usize::try_from(out_ptr) else {
                    return -2;
                };
                let Ok(out_len_usize) = usize::try_from(out_len) else {
                    return -2;
                };

                let mut path_bytes = vec![0u8; path_len_usize];
                if mem
                    .read(&caller, path_usize, path_bytes.as_mut_slice())
                    .is_err()
                {
                    return -1;
                }
                let Ok(path) = String::from_utf8(path_bytes) else {
                    return -2;
                };
                let path = path.trim_matches(char::from(0)).trim().to_string();
                if path.is_empty() {
                    return -2;
                }

                if !is_allowed_log_path(path.as_str()) {
                    return -5;
                }

                let Ok(bytes) = std::fs::read(path.as_str()) else {
                    return -4;
                };

                let n = bytes.len().min(out_len_usize);
                if mem.write(&mut caller, out_usize, &bytes[..n]).is_err() {
                    return -1;
                }
                i32::try_from(n).unwrap_or(i32::MAX)
            },
        )
        .map_err(|e| format!("注册 host function aegis.fs_read_logs 失败: {e}"))?;
    Ok(())
}

fn add_wasm_host_net_connect_virustotal(linker: &mut Linker<WasmHostState>) -> Result<(), String> {
    linker
        .func_wrap(
            "aegis",
            "net_connect_virustotal",
            |mut caller: Caller<'_, WasmHostState>, host_ptr: i32, host_len: i32| -> i32 {
                if !caller.data().permissions.contains("net_connect_virustotal") {
                    return -3;
                }

                let Some(mem) = caller
                    .get_export("memory")
                    .and_then(wasmtime::Extern::into_memory)
                else {
                    return -1;
                };
                let Ok(host_usize) = usize::try_from(host_ptr) else {
                    return -2;
                };
                let Ok(host_len_usize) = usize::try_from(host_len) else {
                    return -2;
                };
                let mut host_bytes = vec![0u8; host_len_usize];
                if mem
                    .read(&caller, host_usize, host_bytes.as_mut_slice())
                    .is_err()
                {
                    return -1;
                }
                let Ok(host) = String::from_utf8(host_bytes) else {
                    return -2;
                };
                let host = host.trim_matches(char::from(0)).trim();
                if host.eq_ignore_ascii_case("virustotal.com")
                    || host.eq_ignore_ascii_case("www.virustotal.com")
                {
                    0
                } else {
                    -5
                }
            },
        )
        .map_err(|e| format!("注册 host function aegis.net_connect_virustotal 失败: {e}"))?;
    Ok(())
}

fn is_allowed_log_path(path: &str) -> bool {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from("C:\\ProgramData"), PathBuf::from);
        let allowed = base.join("Aegis").join("logs");
        let Ok(root) = std::fs::canonicalize(allowed.as_path()) else {
            return false;
        };
        let Ok(resolved) = std::fs::canonicalize(PathBuf::from(path).as_path()) else {
            return false;
        };
        resolved.starts_with(root.as_path())
    }
    #[cfg(not(windows))]
    {
        let Ok(root) = std::fs::canonicalize(PathBuf::from("/var/log").as_path()) else {
            return false;
        };
        let Ok(resolved) = std::fs::canonicalize(PathBuf::from(path).as_path()) else {
            return false;
        };
        resolved.starts_with(root.as_path())
    }
}

fn load_native_plugins(
    base_dir: &Path,
    security: &common::config::SecurityConfig,
    org_public_key: &RsaPublicKey,
    org_pubkey_der: &[u8],
) -> Result<Vec<NativePluginHandle>, String> {
    let isolation = security.native_plugin_isolation.trim();
    let mut plugins: Vec<NativePluginHandle> = Vec::new();
    for raw_path in &security.native_plugin_paths {
        let path = resolve_config_relative_path(base_dir, raw_path.as_str());
        verify_native_plugin_sig(
            security.native_plugin_sig_mode.as_str(),
            org_public_key,
            path.as_path(),
        )?;

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("native_plugin")
            .to_string();

        match isolation {
            "in_process" => {
                let p = load_native_plugin_in_process(path, name)?;
                plugins.push(NativePluginHandle::InProcess(p));
            }
            "subprocess" => {
                let org_pubkey_der_b64 =
                    base64::engine::general_purpose::STANDARD.encode(org_pubkey_der);
                plugins.push(NativePluginHandle::Subprocess(SubprocessNativePlugin {
                    name,
                    path,
                    org_pubkey_der_b64,
                    timeout_ms: security.native_plugin_timeout_ms,
                    sig_mode: security.native_plugin_sig_mode.clone(),
                }));
            }
            other => {
                return Err(format!(
                    "未知 native_plugin_isolation: {other}（仅允许 in_process/subprocess）"
                ));
            }
        }
    }
    Ok(plugins)
}

#[allow(unsafe_code)]
fn load_native_symbol<T: Copy>(lib: &Library, name: &'static [u8]) -> Result<T, libloading::Error> {
    unsafe { lib.get::<T>(name).map(|s| *s) }
}

fn load_native_plugin_in_process(path: PathBuf, name: String) -> Result<NativePlugin, String> {
    #[allow(unsafe_code)]
    let lib = unsafe { Library::new(path.as_path()) }
        .map_err(|e| format!("加载 native 插件失败（{}）: {e}", path.display()))?;

    let abi_version =
        load_native_symbol::<NativeAbiVersion>(&lib, b"aegis_plugin_abi_version\0")
            .map_err(|e| format!("native 插件缺少 abi_version（{}）: {e}", path.display()))?;
    #[allow(unsafe_code)]
    let abi_version = unsafe { abi_version() };
    if abi_version != NATIVE_PLUGIN_ABI_VERSION {
        return Err(format!(
            "native 插件 ABI version 不匹配（{}）: plugin={abi_version}, expected={NATIVE_PLUGIN_ABI_VERSION}",
            path.display()
        ));
    }

    let init = load_native_symbol::<NativeInit>(&lib, b"aegis_plugin_init\0")
        .map_err(|e| format!("native 插件缺少 init（{}）: {e}", path.display()))?;
    let execute = load_native_symbol::<NativeExecute>(&lib, b"aegis_plugin_execute\0")
        .map_err(|e| format!("native 插件缺少 execute（{}）: {e}", path.display()))?;
    let free = load_native_symbol::<NativeFree>(&lib, b"aegis_plugin_free\0")
        .map_err(|e| format!("native 插件缺少 free（{}）: {e}", path.display()))?;
    let shutdown = load_native_symbol::<NativeShutdown>(&lib, b"aegis_plugin_shutdown\0").ok();

    #[allow(unsafe_code)]
    let init_code = unsafe { init() };
    if init_code != 0 {
        return Err(format!(
            "native 插件 init 失败（{}）: code={init_code}",
            path.display()
        ));
    }

    Ok(NativePlugin {
        name,
        path,
        execute,
        free,
        shutdown,
        _library: lib,
    })
}

impl NativePlugin {
    fn execute(&self, input: &[u8]) -> Result<Option<Vec<u8>>, String> {
        const MAX_INPUT: usize = 1024 * 1024;
        const MAX_OUTPUT: usize = 1024 * 1024;
        if input.len() > MAX_INPUT {
            return Err(format!(
                "native input bytes 超限: {} > {}",
                input.len(),
                MAX_INPUT
            ));
        }

        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        #[allow(unsafe_code)]
        let code = unsafe {
            (self.execute)(
                input.as_ptr(),
                input.len(),
                std::ptr::from_mut(&mut out_ptr),
                std::ptr::from_mut(&mut out_len),
            )
        };
        if code != 0 {
            return Err(format!("native execute 返回失败 code={code}"));
        }
        if out_ptr.is_null() || out_len == 0 {
            return Ok(None);
        }
        if out_len > MAX_OUTPUT {
            #[allow(unsafe_code)]
            unsafe {
                (self.free)(out_ptr, out_len);
            }
            return Err(format!(
                "native output bytes 超限: {out_len} > {MAX_OUTPUT}"
            ));
        }

        #[allow(unsafe_code)]
        let bytes = unsafe { std::slice::from_raw_parts(out_ptr, out_len) }.to_vec();
        #[allow(unsafe_code)]
        unsafe {
            (self.free)(out_ptr, out_len);
        }
        Ok(Some(bytes))
    }
}

impl Drop for NativePlugin {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown {
            #[allow(unsafe_code)]
            unsafe {
                shutdown();
            }
        }
    }
}

fn verify_native_plugin_sig(
    sig_mode: &str,
    org_public_key: &RsaPublicKey,
    path: &Path,
) -> Result<(), String> {
    let ed25519_sig_path = path
        .file_name()
        .and_then(|f| f.to_str())
        .map(|f| path.with_file_name(format!("{f}.ed25519.sig")))
        .ok_or_else(|| format!("native 插件路径缺少文件名: {}", path.display()))?;
    let sig_mode = sig_mode.trim();
    if !matches!(sig_mode, "ed25519" | "rsa_pkcs1v15" | "hybrid") {
        return Err(format!("未知 native_plugin_sig_mode: {sig_mode}"));
    }
    if sig_mode == "ed25519" || (sig_mode == "hybrid" && ed25519_sig_path.exists()) {
        let key_bytes = std::env::var_os("AEGIS_SELF_ED25519_PUBKEY_PATH")
            .map(PathBuf::from)
            .and_then(|p| std::fs::read(p.as_path()).ok())
            .or_else(|| embedded_self_ed25519::EMBEDDED_SELF_ED25519_PUBKEY.map(<[u8]>::to_vec))
            .ok_or_else(|| {
                "native_plugin_sig_mode=ed25519/hybrid 但未提供 Self Ed25519 公钥（AEGIS_SELF_ED25519_PUBKEY_PATH 或构建期内嵌）".to_string()
            })?;
        let verifying_key = load_ed25519_verifying_key(key_bytes.as_slice())?;
        return verify_ed25519_file_signature(&verifying_key, path, false, false);
    }

    if sig_mode == "ed25519" {
        return Err(format!(
            "native_plugin_sig_mode=ed25519 需要签名文件: {}",
            ed25519_sig_path.display()
        ));
    }

    let sig_path = path
        .file_name()
        .and_then(|f| f.to_str())
        .map(|f| path.with_file_name(format!("{f}.sig")))
        .ok_or_else(|| format!("native 插件路径缺少文件名: {}", path.display()))?;

    let plugin_bytes = std::fs::read(path)
        .map_err(|e| format!("读取 native 插件失败（{}）: {e}", path.display()))?;
    let sig_bytes = std::fs::read(sig_path.as_path())
        .map_err(|e| format!("读取 native 插件签名失败（{}）: {e}", sig_path.display()))?;

    let signature = parse_sig_bytes(sig_bytes.as_slice())
        .map_err(|e| format!("解析 native 插件签名失败（{}）: {e}", sig_path.display()))?;

    let verifying_key = RsaPkcs1v15VerifyingKey::<Sha256>::new(org_public_key.clone());
    verifying_key
        .verify(plugin_bytes.as_slice(), &signature)
        .map_err(|e| format!("native 插件签名验证失败（{}）: {e}", path.display()))
}

fn parse_sig_bytes(sig_bytes: &[u8]) -> Result<RsaPkcs1v15Signature, String> {
    let text = String::from_utf8(sig_bytes.to_vec()).ok();
    if let Some(text) = text {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(trimmed.as_bytes())
                .map_err(|e| format!("base64 解码失败: {e}"))?;
            return RsaPkcs1v15Signature::try_from(raw.as_slice())
                .map_err(|e| format!("签名字节长度异常: {e}"));
        }
    }
    RsaPkcs1v15Signature::try_from(sig_bytes).map_err(|e| format!("签名字节长度异常: {e}"))
}

fn sign_native_plugin_sig(
    private_key_pem_path: &Path,
    input_path: &Path,
    out_path: &Path,
) -> Result<(), String> {
    let pem = std::fs::read_to_string(private_key_pem_path).map_err(|e| {
        format!(
            "读取签名私钥失败（{}）: {e}",
            private_key_pem_path.display()
        )
    })?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(pem.as_str())
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem.as_str()))
        .map_err(|e| {
            format!(
                "解析 RSA 私钥失败（{}）: {e}",
                private_key_pem_path.display()
            )
        })?;

    let plugin_bytes = std::fs::read(input_path)
        .map_err(|e| format!("读取待签名插件失败（{}）: {e}", input_path.display()))?;

    let signing_key = RsaPkcs1v15SigningKey::<Sha256>::new(private_key);
    let signature: RsaPkcs1v15Signature = signing_key.sign(plugin_bytes.as_slice());

    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_vec());
    let out_text = format!("{sig_b64}\n");
    std::fs::write(out_path, out_text.as_bytes())
        .map_err(|e| format!("写入签名文件失败（{}）: {e}", out_path.display()))?;
    Ok(())
}

#[derive(Debug)]
enum EncryptorCommand {
    Payload(Vec<u8>),
    Flush,
    UpdateIoLimitMb(u32),
    UpdateArtifactConfig(ArtifactConfig),
}

fn main() {
    if let Err(e) = try_main() {
        if e.starts_with("Usage:") {
            println!("{e}");
            std::process::exit(0);
        }
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .build()
        .map_err(|e| format!("初始化 tokio 运行时失败: {e}"))?;
    rt.block_on(run_async())
}

async fn run_async() -> Result<(), String> {
    let args = parse_args(std::env::args().skip(1))?;
    if let Some(worker) = args.native_plugin_worker {
        run_native_plugin_worker(worker)?;
        return Ok(());
    }

    init_telemetry().map_err(|e| format!("初始化日志失败: {e}"))?;
    if let Some(sign) = args.sign_plugin.as_ref() {
        sign_native_plugin_sig(
            sign.key_pem.as_path(),
            sign.input_file.as_path(),
            sign.sig_out.as_path(),
        )?;
        return Ok(());
    }

    let (bus_tx, bus_rx) = tokio_mpsc::unbounded_channel::<EncryptorCommand>();
    let (mgr, rule_mgr, encryptor_tx, plugins, base_dir) = init_runtime(args, &bus_tx)?;

    tokio::spawn(forward_encryptor(bus_rx, encryptor_tx));

    run_forever_async(&mgr, &rule_mgr, &plugins, base_dir.as_path(), &bus_tx).await;
    Ok(())
}

async fn forward_encryptor(mut bus_rx: EventBusRx, encryptor_tx: mpsc::Sender<EncryptorCommand>) {
    while let Some(cmd) = bus_rx.recv().await {
        if encryptor_tx.send(cmd).is_err() {
            break;
        }
    }
}

fn init_runtime(
    args: ProbeArgs,
    bus_tx: &EventBusTx,
) -> Result<
    (
        ConfigManager,
        RuleManager,
        mpsc::Sender<EncryptorCommand>,
        PluginManager,
        PathBuf,
    ),
    String,
> {
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

    maybe_self_validate_best_effort(
        is_unsigned_build(),
        out_dir.as_path(),
        config_path.as_path(),
        &cfg.security,
    )?;

    let plugins = PluginManager::load(
        out_dir.as_path(),
        &cfg.security,
        &org_public_key,
        org_pubkey_der.as_slice(),
    )?;
    tracing::info!(
        wasm_plugins = plugins.wasm_count(),
        wasm_plugin_names = ?plugins.wasm_plugin_names(),
        wasm_plugin_entries = ?plugins.wasm_plugin_entries(),
        native_plugins = plugins.native_count(),
        native_plugin_names = ?plugins.native_plugin_names(),
        native_plugin_entries = ?plugins.native_plugin_entries(),
        "plugins loaded"
    );

    let encryptor_tx = spawn_encryptor(
        out_dir.clone(),
        org_public_key,
        org_key_fp,
        uuid_mode,
        user_passphrase,
        cfg.governor.effective_profile_applied().io_limit_mb,
        cfg.artifact.clone(),
    );
    enqueue_payload(
        bus_tx,
        None,
        PayloadEnvelope::system_info(build_system_info()).encode_to_vec(),
    );

    let rule_config_path = config_path.clone();
    let mut mgr = ConfigManager::from_config(config_path, cfg)
        .map_err(|e| format!("初始化配置管理器失败: {e}"))?;
    mgr.start_watching()
        .map_err(|e| format!("启动配置热加载失败: {e}"))?;

    let mut rule_mgr =
        RuleManager::load(rule_config_path).map_err(|e| format!("初始化检测规则失败: {e}"))?;
    rule_mgr
        .start_watching()
        .map_err(|e| format!("启动检测规则热加载失败: {e}"))?;

    Ok((mgr, rule_mgr, encryptor_tx, plugins, out_dir))
}

struct BloomFilter {
    bits: Vec<u8>,
    k: u8,
}

impl BloomFilter {
    fn from_bytes_best_effort(bytes: &[u8]) -> Option<Self> {
        if bytes.len() >= 10 && bytes.get(0..4) == Some(b"AEBF") {
            let version = *bytes.get(4)?;
            if version != 1 {
                return None;
            }
            let k = *bytes.get(5)?;
            let bits_len = u32::from_le_bytes(bytes.get(6..10)?.try_into().ok()?) as usize;
            let start = 10usize;
            let end = start.saturating_add(bits_len);
            let bits = bytes.get(start..end)?.to_vec();
            if bits.is_empty() {
                return None;
            }
            let k = k.clamp(1, 32);
            return Some(Self { bits, k });
        }

        if bytes.is_empty() {
            return None;
        }
        Some(Self {
            bits: bytes.to_vec(),
            k: 7,
        })
    }

    fn contains(&self, item: &str) -> bool {
        let normalized = item.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return false;
        }
        let m_bits = u64::try_from(self.bits.len()).unwrap_or(u64::MAX) * 8;
        if m_bits == 0 {
            return false;
        }
        let digest = Sha256::digest(normalized.as_bytes());
        let digest_bytes = digest.as_slice();
        let mut h1_bytes = [0u8; 8];
        let mut h2_bytes = [0u8; 8];
        h1_bytes.copy_from_slice(&digest_bytes[0..8]);
        h2_bytes.copy_from_slice(&digest_bytes[8..16]);
        let h1 = u64::from_le_bytes(h1_bytes);
        let mut h2 = u64::from_le_bytes(h2_bytes);
        if h2 == 0 {
            h2 = 0x9e37_79b9_7f4a_7c15;
        }
        let hash_count = u64::from(self.k);
        for i in 0..hash_count {
            let idx = h1.wrapping_add(h2.wrapping_mul(i)).rem_euclid(m_bits);
            if !bit_is_set(self.bits.as_slice(), idx) {
                return false;
            }
        }
        true
    }
}

fn bit_is_set(bytes: &[u8], bit_index: u64) -> bool {
    let byte = usize::try_from(bit_index / 8).unwrap_or(usize::MAX);
    let bit = u8::try_from(bit_index % 8).unwrap_or(u8::MAX);
    let Some(v) = bytes.get(byte) else {
        return false;
    };
    (v & (1u8 << bit)) != 0
}

struct SmartReflexEngine {
    bloom: Option<BloomFilter>,
    bloom_path: PathBuf,
    feed: HashSet<String>,
    feed_path: PathBuf,
    next_reload_at: Instant,
    last_bloom_mtime: Option<SystemTime>,
    last_feed_mtime: Option<SystemTime>,
}

#[derive(Clone, Copy)]
enum SmartReflexSource {
    Bloom,
    Feed,
}

impl SmartReflexEngine {
    fn load_best_effort(base_dir: &Path) -> Self {
        let bloom_path = base_dir.join("c2_bloom.bin");
        let (bloom, last_bloom_mtime) = Self::load_bloom_best_effort(bloom_path.as_path());
        let feed_path = base_dir.join("community_feed.txt");
        let (feed, last_feed_mtime) = Self::load_feed_best_effort(feed_path.as_path());
        Self {
            bloom,
            bloom_path,
            feed,
            feed_path,
            next_reload_at: Instant::now(),
            last_bloom_mtime,
            last_feed_mtime,
        }
    }

    fn maybe_reload(&mut self) {
        if self.next_reload_at > Instant::now() {
            return;
        }
        self.next_reload_at = Instant::now() + Duration::from_secs(30);

        if let Some(m) = std::fs::metadata(self.bloom_path.as_path())
            .ok()
            .and_then(|m| m.modified().ok())
        {
            if self.last_bloom_mtime.is_none_or(|v| v != m) {
                let (bloom, mtime) = Self::load_bloom_best_effort(self.bloom_path.as_path());
                if bloom.is_some() {
                    self.bloom = bloom;
                    self.last_bloom_mtime = mtime;
                }
            }
        } else if self.bloom.is_none() {
            let (bloom, mtime) = Self::load_bloom_best_effort(self.bloom_path.as_path());
            if bloom.is_some() {
                self.bloom = bloom;
                self.last_bloom_mtime = mtime;
            }
        }

        if let Some(m) = std::fs::metadata(self.feed_path.as_path())
            .ok()
            .and_then(|m| m.modified().ok())
        {
            if self.last_feed_mtime.is_none_or(|v| v != m) {
                let (feed, mtime) = Self::load_feed_best_effort(self.feed_path.as_path());
                if !feed.is_empty() {
                    self.feed = feed;
                    self.last_feed_mtime = mtime;
                }
            }
        } else if self.feed.is_empty() {
            let (feed, mtime) = Self::load_feed_best_effort(self.feed_path.as_path());
            if !feed.is_empty() {
                self.feed = feed;
                self.last_feed_mtime = mtime;
            }
        }
    }

    fn has_indicators(&self) -> bool {
        self.bloom.is_some() || !self.feed.is_empty()
    }

    fn matches_text(&mut self, text: &str) -> Vec<(String, SmartReflexSource)> {
        self.maybe_reload();

        let mut out: Vec<(String, SmartReflexSource)> = Vec::new();
        for tok in tokenize_indicators(text) {
            if tok.len() > 253 {
                continue;
            }
            let indicator = normalize_indicator(tok.as_str());
            if indicator.is_empty() {
                continue;
            }
            if out.iter().any(|(s, _)| s == &indicator) {
                continue;
            }
            let in_feed = self.feed.contains(indicator.as_str());
            let in_bloom = self
                .bloom
                .as_ref()
                .is_some_and(|b| b.contains(indicator.as_str()));
            if in_feed || in_bloom {
                let source = if in_feed {
                    SmartReflexSource::Feed
                } else {
                    SmartReflexSource::Bloom
                };
                out.push((indicator, source));
                if out.len() >= 4 {
                    break;
                }
            }
        }
        out
    }

    fn load_bloom_best_effort(path: &Path) -> (Option<BloomFilter>, Option<SystemTime>) {
        let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
        let bloom = std::fs::read(path)
            .ok()
            .and_then(|b| BloomFilter::from_bytes_best_effort(b.as_slice()));
        (bloom, mtime)
    }

    fn load_feed_best_effort(path: &Path) -> (HashSet<String>, Option<SystemTime>) {
        let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
        let Ok(bytes) = std::fs::read(path) else {
            return (HashSet::new(), mtime);
        };
        let text = String::from_utf8_lossy(bytes.as_slice());
        let mut out: HashSet<String> = HashSet::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let indicator = normalize_indicator(line);
            if indicator.is_empty() {
                continue;
            }
            out.insert(indicator);
        }
        (out, mtime)
    }
}

fn tokenize_indicators(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| {
        !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '/' | '\\'))
    })
    .filter(|s| !s.is_empty())
    .map(ToString::to_string)
}

fn normalize_indicator(raw: &str) -> String {
    let s = raw
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'' || c == ',' || c == ';');
    if s.is_empty() {
        return String::new();
    }
    let mut s = s.to_ascii_lowercase();
    if let Some(pos) = s.find("://") {
        s = s[pos + 3..].to_string();
    }
    if let Some(pos) = s.find('/') {
        s = s[..pos].to_string();
    }
    if let Some(pos) = s.find('\\') {
        s = s[..pos].to_string();
    }
    if let Some(pos) = s.rfind(':') {
        let (host, port) = s.split_at(pos);
        if port.len() > 1 && port[1..].chars().all(|c| c.is_ascii_digit()) {
            s = host.to_string();
        }
    }
    if !s.contains('.') {
        return String::new();
    }
    if s.starts_with('.') || s.ends_with('.') || s.contains("..") {
        return String::new();
    }
    s
}

fn emit_smart_reflex_from_process_payload_best_effort(
    state: &mut LoopState,
    governor: &mut Governor,
    bus_tx: &EventBusTx,
    payload: &[u8],
) {
    if !state.smart_reflex.has_indicators() {
        state.smart_reflex.maybe_reload();
        if !state.smart_reflex.has_indicators() {
            return;
        }
    }
    if !governor.try_consume_budget(1) {
        return;
    }
    let Ok(env) = PayloadEnvelope::decode(payload) else {
        return;
    };
    let Some(payload_envelope::Payload::ProcessInfo(p)) = env.payload else {
        return;
    };

    let mut indicators: Vec<(String, SmartReflexSource)> = Vec::new();
    indicators.extend(state.smart_reflex.matches_text(p.cmdline.as_str()));
    indicators.extend(state.smart_reflex.matches_text(p.exe_path.as_str()));

    for (indicator, source) in indicators {
        if !governor.try_consume_budget(1) {
            break;
        }
        let ev = SmartReflexEvidence {
            matched_at: unix_timestamp_now(),
            score: 80,
            kind: match source {
                SmartReflexSource::Bloom => "c2_bloom",
                SmartReflexSource::Feed => "community_feed",
            }
            .to_string(),
            indicator,
            pid: p.pid,
            exec_id: p.exec_id,
        };
        enqueue_payload(
            bus_tx,
            Some(&state.dropped_counter),
            PayloadEnvelope::smart_reflex_evidence(ev).encode_to_vec(),
        );
    }
}

#[cfg(target_os = "linux")]
fn emit_smart_reflex_from_ebpf_events_best_effort(
    state: &mut LoopState,
    governor: &mut Governor,
    bus_tx: &EventBusTx,
    events: &[EbpfEvent],
) {
    if !state.smart_reflex.has_indicators() {
        state.smart_reflex.maybe_reload();
        if !state.smart_reflex.has_indicators() {
            return;
        }
    }
    if !governor.try_consume_budget(1) {
        return;
    }

    let mut emitted: u32 = 0;
    for ev in events {
        if emitted >= 8 {
            break;
        }
        if ev.detail.trim().is_empty() {
            continue;
        }
        let indicators = state.smart_reflex.matches_text(ev.detail.as_str());
        for (indicator, source) in indicators {
            if emitted >= 8 {
                break;
            }
            if !governor.try_consume_budget(1) {
                return;
            }
            let prefix = match source {
                SmartReflexSource::Bloom => "c2_bloom",
                SmartReflexSource::Feed => "community_feed",
            };
            let out = SmartReflexEvidence {
                matched_at: unix_timestamp_now(),
                score: 70,
                kind: format!("{prefix}_{}", ev.kind),
                indicator,
                pid: ev.pid,
                exec_id: ev.exec_id,
            };
            enqueue_payload(
                bus_tx,
                Some(&state.dropped_counter),
                PayloadEnvelope::smart_reflex_evidence(out).encode_to_vec(),
            );
            emitted = emitted.saturating_add(1);
        }
    }
}

fn emit_plugin_outputs_governed(
    state: &mut LoopState,
    governor: &mut Governor,
    plugins: &PluginManager,
    bus_tx: &EventBusTx,
    input: &[u8],
) {
    let outputs = plugins.execute_governed(governor, input);
    if outputs.is_empty() {
        return;
    }

    let mut any = false;
    for bytes in outputs {
        if !governor.try_consume_budget(1) {
            break;
        }
        let Ok(env) = PayloadEnvelope::decode(bytes.as_slice()) else {
            state.dropped_counter.add(1);
            continue;
        };
        if env.payload.is_none() {
            continue;
        }
        any = true;
        enqueue_payload(bus_tx, Some(&state.dropped_counter), env.encode_to_vec());
    }

    if any && bus_tx.send(EncryptorCommand::Flush).is_err() {
        state.dropped_counter.add(1);
        tracing::warn!("encryptor channel closed");
    }
}

fn maybe_self_validate_best_effort(
    is_unsigned_build: bool,
    base_dir: &Path,
    config_path: &Path,
    security: &common::config::SecurityConfig,
) -> Result<(), String> {
    let key_bytes = std::env::var_os("AEGIS_SELF_ED25519_PUBKEY_PATH")
        .map(PathBuf::from)
        .and_then(|p| std::fs::read(p.as_path()).ok())
        .or_else(|| embedded_self_ed25519::EMBEDDED_SELF_ED25519_PUBKEY.map(<[u8]>::to_vec));

    let Some(key_bytes) = key_bytes else {
        return Ok(());
    };

    let verifying_key = load_ed25519_verifying_key(key_bytes.as_slice())?;
    let exe = std::env::current_exe().map_err(|e| format!("获取当前可执行文件路径失败: {e}"))?;
    verify_ed25519_file_signature(&verifying_key, exe.as_path(), true, is_unsigned_build)?;

    verify_ed25519_file_signature(&verifying_key, config_path, false, false)?;
    for raw in &security.yara_rule_paths {
        let p = resolve_config_relative_path(base_dir, raw.as_str());
        verify_ed25519_file_signature(&verifying_key, p.as_path(), false, false)?;
    }
    Ok(())
}

fn load_ed25519_verifying_key(bytes: &[u8]) -> Result<Ed25519VerifyingKey, String> {
    let raw = parse_ed25519_pubkey_bytes(bytes)?;
    let key: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "Ed25519 public key 长度必须为 32 bytes".to_string())?;
    Ed25519VerifyingKey::from_bytes(&key).map_err(|e| format!("解析 Ed25519 public key 失败: {e}"))
}

fn parse_ed25519_pubkey_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let text = String::from_utf8(bytes.to_vec()).ok();
    if let Some(text) = text {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(trimmed.as_bytes())
                .map_err(|e| format!("base64 解码失败: {e}"))?;
            if raw.len() == 32 {
                return Ok(raw);
            }
        }
    }
    if bytes.len() == 32 {
        return Ok(bytes.to_vec());
    }
    Err("Ed25519 public key 格式无效".to_string())
}

fn parse_ed25519_sig_bytes(sig_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let text = String::from_utf8(sig_bytes.to_vec()).ok();
    if let Some(text) = text {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(trimmed.as_bytes())
                .map_err(|e| format!("base64 解码失败: {e}"))?;
            if raw.len() == 64 {
                return Ok(raw);
            }
        }
    }
    if sig_bytes.len() == 64 {
        return Ok(sig_bytes.to_vec());
    }
    Err("Ed25519 signature 格式无效".to_string())
}

fn verify_ed25519_file_signature(
    verifying_key: &Ed25519VerifyingKey,
    file_path: &Path,
    is_self_exe: bool,
    allow_missing_sig: bool,
) -> Result<(), String> {
    let sig_path = file_path
        .file_name()
        .and_then(|f| f.to_str())
        .map(|f| file_path.with_file_name(format!("{f}.ed25519.sig")))
        .ok_or_else(|| format!("路径缺少文件名: {}", file_path.display()))?;

    if !sig_path.exists() {
        if allow_missing_sig {
            return Ok(());
        }
        if is_self_exe {
            return Err(format!("缺少自校验签名文件: {}", sig_path.display()));
        }
        return Err(format!("缺少签名文件: {}", sig_path.display()));
    }

    let file_bytes = std::fs::read(file_path)
        .map_err(|e| format!("读取文件失败（{}）: {e}", file_path.display()))?;
    let sig_bytes = std::fs::read(sig_path.as_path())
        .map_err(|e| format!("读取签名失败（{}）: {e}", sig_path.display()))?;
    let raw = parse_ed25519_sig_bytes(sig_bytes.as_slice())
        .map_err(|e| format!("解析签名失败（{}）: {e}", sig_path.display()))?;
    let sig: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "Ed25519 signature 长度必须为 64 bytes".to_string())?;
    let sig = Ed25519Signature::from_bytes(&sig);
    verifying_key
        .verify_strict(file_bytes.as_slice(), &sig)
        .map_err(|e| format!("Ed25519 签名验证失败（{}）: {e}", file_path.display()))?;
    Ok(())
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
    smart_reflex: SmartReflexEngine,
    #[cfg(target_os = "linux")]
    last_bpf_snapshot: Instant,
    #[cfg(target_os = "linux")]
    last_linux_kernel_forensics: Instant,
    #[cfg(target_os = "linux")]
    last_ebpf_poll: Instant,
    #[cfg(target_os = "linux")]
    last_ebpf_open_attempt: Instant,
    #[cfg(target_os = "linux")]
    last_ebpf_attach_attempt: Instant,
    #[cfg(target_os = "linux")]
    last_ebpf_exec_id_open_attempt: Instant,
    #[cfg(target_os = "linux")]
    ebpf_ringbuf: Option<common::collectors::linux::RingbufReader>,
    #[cfg(target_os = "linux")]
    ebpf_producer: Option<common::collectors::linux::EbpfProducer>,
    #[cfg(target_os = "linux")]
    ebpf_exec_id_map: Option<std::os::fd::OwnedFd>,
}

impl LoopState {
    fn new(base_dir: &Path) -> Self {
        let smart_reflex = SmartReflexEngine::load_best_effort(base_dir);
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
            smart_reflex,
            #[cfg(target_os = "linux")]
            last_bpf_snapshot: Instant::now(),
            #[cfg(target_os = "linux")]
            last_linux_kernel_forensics: Instant::now(),
            #[cfg(target_os = "linux")]
            last_ebpf_poll: Instant::now(),
            #[cfg(target_os = "linux")]
            last_ebpf_open_attempt: Instant::now(),
            #[cfg(target_os = "linux")]
            last_ebpf_attach_attempt: Instant::now(),
            #[cfg(target_os = "linux")]
            last_ebpf_exec_id_open_attempt: Instant::now(),
            #[cfg(target_os = "linux")]
            ebpf_ringbuf: None,
            #[cfg(target_os = "linux")]
            ebpf_producer: None,
            #[cfg(target_os = "linux")]
            ebpf_exec_id_map: None,
        }
    }
}

async fn run_forever_async(
    mgr: &ConfigManager,
    rule_mgr: &RuleManager,
    plugins: &PluginManager,
    base_dir: &Path,
    bus_tx: &EventBusTx,
) {
    tracing::info!("probe started");
    let initial_cfg = mgr.current();
    let mut governor = Governor::new(&initial_cfg.governor);
    let mut state = LoopState::new(base_dir);
    tokio::spawn(community_feed_autopull_loop(base_dir.to_path_buf()));
    let mut last_encryptor_io_limit_mb: Option<u32> = None;
    let mut last_artifact_cfg: Option<ArtifactConfig> = None;

    loop {
        let cfg = mgr.current();
        let rules = rule_mgr.current();
        let governor_cfg = cfg.governor.effective_profile_applied();
        governor.apply_config(&governor_cfg);
        let (cpu_usage_percent, sleep) = governor.tick_with_usage();

        if last_encryptor_io_limit_mb != Some(governor_cfg.io_limit_mb) {
            if bus_tx
                .send(EncryptorCommand::UpdateIoLimitMb(governor_cfg.io_limit_mb))
                .is_err()
            {
                tracing::warn!("encryptor channel closed");
            }
            last_encryptor_io_limit_mb = Some(governor_cfg.io_limit_mb);
        }

        if last_artifact_cfg.as_ref() != Some(&cfg.artifact) {
            if bus_tx
                .send(EncryptorCommand::UpdateArtifactConfig(cfg.artifact.clone()))
                .is_err()
            {
                tracing::warn!("encryptor channel closed");
            }
            last_artifact_cfg = Some(cfg.artifact.clone());
        }

        #[cfg(target_os = "linux")]
        {
            maybe_attach_aegis_ebpf_best_effort(&mut state, &mut governor, &cfg.security);
        }

        maybe_emit_process_snapshot(&mut state, &mut governor, cfg.as_ref(), plugins, bus_tx);
        maybe_emit_file_snapshot(&mut state, &mut governor, rules.as_ref(), bus_tx);
        maybe_emit_network_update(&mut state, &mut governor, bus_tx);
        maybe_emit_linux_bpf_snapshot(&mut state, &mut governor);
        maybe_emit_linux_kernel_forensics_evidence(&mut state, &mut governor, bus_tx);
        maybe_emit_linux_ebpf_events(&mut state, &mut governor, &cfg.security, bus_tx);
        maybe_emit_telemetry(
            &mut state,
            cfg.as_ref(),
            &mut governor,
            bus_tx,
            cpu_usage_percent,
        );

        tokio::time::sleep(Duration::from_millis(50).saturating_add(sleep)).await;
    }
}

fn maybe_emit_process_snapshot(
    state: &mut LoopState,
    governor: &mut Governor,
    cfg: &common::config::AegisConfig,
    plugins: &PluginManager,
    bus_tx: &EventBusTx,
) {
    if state.last_process_snapshot.elapsed() < Duration::from_secs(60) {
        return;
    }
    if !governor.try_consume_budget(1) {
        return;
    }

    let processes = collect_process_snapshot(
        governor,
        &state.process_exec_id_counter,
        cfg.security.ebpf_pin_dir.as_deref(),
        64,
    );
    let total = processes.len();
    let mut sent: usize = 0;
    for p in processes {
        let is_ghost = p.is_ghost;
        #[cfg(windows)]
        let pid = p.pid;
        #[cfg(windows)]
        let exec_id = p.exec_id;
        #[cfg(windows)]
        let exe_path = p.exe_path.clone();

        if !governor.try_consume_budget(1) {
            let dropped = u64::try_from(total.saturating_sub(sent)).unwrap_or(u64::MAX);
            state.dropped_counter.add(dropped);
            break;
        }
        let encoded = PayloadEnvelope::process_info(p).encode_to_vec();
        enqueue_payload(bus_tx, Some(&state.dropped_counter), encoded.clone());
        sent = sent.saturating_add(1);

        emit_smart_reflex_from_process_payload_best_effort(
            state,
            governor,
            bus_tx,
            encoded.as_slice(),
        );
        emit_plugin_outputs_governed(state, governor, plugins, bus_tx, encoded.as_slice());

        if is_ghost {
            #[cfg(windows)]
            {
                if let Some(ev) =
                    common::collectors::windows::collect_process_ghosting_evidence_governed(
                        governor,
                        pid,
                        exe_path.as_str(),
                    )
                    && governor.try_consume_budget(1)
                {
                    enqueue_payload(
                        bus_tx,
                        Some(&state.dropped_counter),
                        PayloadEnvelope::process_ghosting_evidence(ev).encode_to_vec(),
                    );
                }

                if let Some(ev) =
                    common::collectors::windows::collect_windows_memory_forensics_evidence_governed_with_depth(
                        governor,
                        pid,
                        exec_id,
                        cfg.forensics.windows_memory_scan_depth,
                    )
                    && governor.try_consume_budget(1)
                {
                    enqueue_payload(
                        bus_tx,
                        Some(&state.dropped_counter),
                        PayloadEnvelope::windows_memory_forensics_evidence(ev).encode_to_vec(),
                    );
                }
            }
        }
    }
    state.last_process_snapshot = Instant::now();
}

fn maybe_emit_file_snapshot(
    state: &mut LoopState,
    governor: &mut Governor,
    rules: &RuleSet,
    bus_tx: &EventBusTx,
) {
    if state.last_file_snapshot.elapsed() < effective_file_snapshot_interval() {
        return;
    }
    if rules.scan_whitelist().is_empty() {
        state.last_file_snapshot = Instant::now();
        return;
    }
    if !governor.try_consume_budget(1) {
        return;
    }

    #[cfg(windows)]
    emit_windows_usn_journal_best_effort(state, governor, rules, bus_tx);

    let files = collect_file_snapshot(governor, rules);
    let total = files.len();
    let mut sent: usize = 0;
    for f in files {
        if !governor.try_consume_budget(1) {
            let dropped = u64::try_from(total.saturating_sub(sent)).unwrap_or(u64::MAX);
            state.dropped_counter.add(dropped);
            break;
        }
        enqueue_payload(
            bus_tx,
            Some(&state.dropped_counter),
            PayloadEnvelope::file_info(f).encode_to_vec(),
        );
        sent = sent.saturating_add(1);
    }
    state.last_file_snapshot = Instant::now();
}

#[cfg(windows)]
fn emit_windows_usn_journal_best_effort(
    state: &mut LoopState,
    governor: &mut Governor,
    rules: &RuleSet,
    bus_tx: &EventBusTx,
) {
    if !governor.try_consume_budget(1) {
        return;
    }

    let mut drives: Vec<char> = rules
        .scan_whitelist()
        .iter()
        .filter_map(|p| common::collectors::windows::drive_letter(Path::new(p)))
        .map(|d| d.to_ascii_uppercase())
        .collect();
    drives.sort_unstable();
    drives.dedup();

    for d in drives {
        if !governor.try_consume_budget(1) {
            break;
        }

        let Some(bytes) = common::collectors::windows::collect_usn_journal_tsv_best_effort(
            governor, d, 2000, 2_000_000,
        ) else {
            continue;
        };

        let drive_u8 = u8::try_from(d as u32).unwrap_or(0);
        let now = u64::try_from(unix_timestamp_now()).unwrap_or(0);
        let evidence_id = (now << 8) | u64::from(drive_u8);
        let Ok(chunker) = EvidenceChunker::new(
            bytes.as_slice(),
            512 * 1024,
            evidence_id,
            format!("windows_usn_journal:{d}"),
            "text/tab-separated-values",
        ) else {
            continue;
        };

        for env in chunker {
            if !governor.try_consume_budget(1) {
                state.dropped_counter.add(1);
                break;
            }
            enqueue_payload(bus_tx, Some(&state.dropped_counter), env.encode_to_vec());
        }
    }
}

fn maybe_emit_network_update(state: &mut LoopState, governor: &mut Governor, bus_tx: &EventBusTx) {
    if state.last_network_snapshot.elapsed() < Duration::from_secs(60) {
        return;
    }
    if !governor.try_consume_budget(1) {
        return;
    }

    let ip_addresses = collect_ip_addresses();
    if ip_addresses != state.last_ip_addresses {
        let mut ts = unix_timestamp_now();
        if ts <= state.last_network_update_ts {
            ts = state.last_network_update_ts.saturating_add(1);
        }
        enqueue_payload(
            bus_tx,
            Some(&state.dropped_counter),
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

fn collect_file_snapshot(governor: &mut Governor, rules: &RuleSet) -> Vec<FileInfo> {
    #[cfg(windows)]
    {
        let mut by_drive: BTreeMap<Option<char>, Vec<String>> = BTreeMap::new();
        for p in rules.scan_whitelist() {
            let drive = common::collectors::windows::drive_letter(Path::new(p));
            by_drive.entry(drive).or_default().push(p.clone());
        }

        let mut out = Vec::new();
        for (drive, paths) in by_drive {
            let snapshot = drive.and_then(|d| {
                if vss_fast_mode() || paths.iter().any(|p| file_should_use_vss(Path::new(p))) {
                    create_vss_snapshot_for_drive(d)
                } else {
                    None
                }
            });
            if snapshot.is_some() {
                let hold = vss_hold_duration();
                if hold > Duration::from_millis(0) {
                    thread::sleep(hold);
                }
            }
            let (vss_drive, vss_device_path) = snapshot.as_ref().map_or((None, None), |s| {
                (Some(s.drive_letter), Some(s.device_path.as_str()))
            });

            let mut infos = common::collectors::windows::collect_file_infos_governed(
                Some(governor),
                paths.as_slice(),
                rules.timestomp_threshold_ms(),
                vss_drive,
                vss_device_path,
            );
            out.append(&mut infos);
        }
        out
    }
    #[cfg(not(windows))]
    {
        let _ = (governor, rules);
        Vec::new()
    }
}

fn truthy_env(key: &str) -> bool {
    std::env::var(key).ok().is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        v == "1" || v == "true" || v == "yes"
    })
}

fn read_env_string(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn read_env_u64(name: &str) -> Option<u64> {
    read_env_string(name).and_then(|s| s.parse::<u64>().ok())
}

fn read_env_usize(name: &str) -> Option<usize> {
    read_env_string(name).and_then(|s| s.parse::<usize>().ok())
}

fn parse_community_feed_text(text: &str) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let indicator = normalize_indicator(line);
        if indicator.is_empty() {
            continue;
        }
        out.insert(indicator);
    }
    out
}

fn write_atomic_best_effort(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::other("target path has no parent dir"));
    };
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| std::io::Error::other("target path has no filename"))?;
    let tmp = parent.join(format!("{file_name}.tmp"));
    let backup = parent.join(format!("{file_name}.bak"));

    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(tmp.as_path())?;
    f.write_all(bytes)?;
    f.flush()?;
    let _sync_all_ignored = f.sync_all();
    drop(f);

    let _remove_backup_ignored = std::fs::remove_file(backup.as_path());
    if path.exists() && std::fs::rename(path, backup.as_path()).is_err() {
        let _remove_tmp_ignored = std::fs::remove_file(tmp.as_path());
        return Err(std::io::Error::other(
            "backup existing community feed failed",
        ));
    }

    match std::fs::rename(tmp.as_path(), path) {
        Ok(()) => {
            let _remove_backup_ignored = std::fs::remove_file(backup.as_path());
            Ok(())
        }
        Err(e) => {
            if backup.exists() {
                let _restore_backup_ignored = std::fs::rename(backup.as_path(), path);
            }
            let _remove_tmp_ignored = std::fs::remove_file(tmp.as_path());
            Err(e)
        }
    }
}

async fn community_feed_autopull_loop(base_dir: PathBuf) {
    let Some(url) = read_env_string("AEGIS_COMMUNITY_FEED_URL") else {
        return;
    };

    let interval_secs = read_env_u64("AEGIS_COMMUNITY_FEED_PULL_INTERVAL_SECS")
        .unwrap_or(3600)
        .clamp(60, 86400 * 30);
    let timeout_secs = read_env_u64("AEGIS_COMMUNITY_FEED_TIMEOUT_SECS")
        .unwrap_or(10)
        .clamp(2, 60);
    let max_bytes = read_env_usize("AEGIS_COMMUNITY_FEED_MAX_BYTES")
        .unwrap_or(2_000_000)
        .clamp(1024, 20_000_000);

    let client = match reqwest::Client::builder()
        .user_agent("AegisProbe/0.0.1")
        .timeout(Duration::from_secs(timeout_secs))
        .build()
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "init community feed http client failed");
            return;
        }
    };

    let feed_path = base_dir.join("community_feed.txt");

    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let _ = ticker.tick().await;

        let should_fetch = match std::fs::metadata(feed_path.as_path())
            .ok()
            .and_then(|m| m.modified().ok())
        {
            None => true,
            Some(mtime) => match SystemTime::now().duration_since(mtime) {
                Ok(age) => age >= Duration::from_secs(interval_secs),
                Err(_) => true,
            },
        };
        if !should_fetch {
            continue;
        }

        let resp = match client.get(url.as_str()).send().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "pull community feed failed");
                continue;
            }
        };

        if !resp.status().is_success() {
            tracing::warn!(status = %resp.status(), "pull community feed non-success status");
            continue;
        }

        if let Some(len) = resp.content_length()
            && usize::try_from(len).ok().is_some_and(|v| v > max_bytes)
        {
            tracing::warn!(content_length = len, max_bytes, "community feed too large");
            continue;
        }

        let bytes = match resp.bytes().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "read community feed body failed");
                continue;
            }
        };
        if bytes.len() > max_bytes {
            tracing::warn!(bytes = bytes.len(), max_bytes, "community feed too large");
            continue;
        }

        let text = String::from_utf8_lossy(bytes.as_ref());
        let parsed = parse_community_feed_text(text.as_ref());
        if parsed.is_empty() {
            tracing::warn!("pulled community feed has no valid indicators");
            continue;
        }

        if let Err(e) = write_atomic_best_effort(feed_path.as_path(), bytes.as_ref()) {
            tracing::warn!(error = %e, "write community feed failed");
            continue;
        }

        tracing::info!(indicators = parsed.len(), "community feed updated");
    }
}

fn vss_fast_mode() -> bool {
    truthy_env("AEGIS_VSS_FAST")
}

#[cfg(windows)]
fn vss_ps_fallback_enabled() -> bool {
    vss_fast_mode() || truthy_env("AEGIS_VSS_PS_FALLBACK")
}

#[cfg(windows)]
fn vss_fallback_enabled_for_error(err: &impl std::fmt::Display) -> bool {
    if vss_ps_fallback_enabled() {
        return true;
    }
    let s = err.to_string();
    s.contains("0x80041014") || s.contains("0x80041002")
}

#[cfg(windows)]
fn vss_hold_duration() -> Duration {
    if vss_fast_mode() {
        return Duration::from_secs(2);
    }
    Duration::from_millis(0)
}

fn effective_file_snapshot_interval() -> Duration {
    if vss_fast_mode() {
        return Duration::from_secs(5);
    }
    Duration::from_secs(300)
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
        if delete_vss_snapshot(self.shadow_id.as_str()).is_err() {
            let _ignored = delete_vss_snapshot_vssadmin(self.shadow_id.as_str());
        }
    }
}

#[cfg(windows)]
fn delete_vss_snapshot(shadow_id: &str) -> std::io::Result<()> {
    fn io_err(e: impl std::fmt::Display) -> std::io::Error {
        std::io::Error::other(e.to_string())
    }

    #[allow(non_camel_case_types)]
    #[derive(serde::Deserialize)]
    struct Win32_ShadowCopy;

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
        .exec_instance_method::<Win32_ShadowCopy, _>(instance.path.as_str(), "Delete", ())
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
fn delete_vss_snapshot_vssadmin(shadow_id: &str) -> std::io::Result<()> {
    use std::process::Command;

    fn io_err(e: impl std::fmt::Display) -> std::io::Error {
        std::io::Error::other(e.to_string())
    }

    let arg_shadow = format!("/shadow={shadow_id}");
    let out = Command::new(windows_find_vssadmin_exe())
        .args(["delete", "shadows", arg_shadow.as_str(), "/quiet"])
        .output()
        .map_err(io_err)?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(out.stderr.as_slice())
            .trim()
            .to_string();
        if stderr.is_empty() {
            Err(std::io::Error::other("vssadmin delete shadows failed"))
        } else {
            Err(std::io::Error::other(stderr))
        }
    }
}

#[cfg(windows)]
fn normalize_volume_arg(volume: &str) -> String {
    let v = volume.trim();
    if let Some(rest) = v.strip_suffix("\\") {
        return rest.to_string();
    }
    v.to_string()
}

#[cfg(windows)]
fn windows_system32_exe_path(relative: &str) -> std::path::PathBuf {
    let sysroot = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .unwrap_or_else(|| "C:\\Windows".into());
    std::path::PathBuf::from(sysroot)
        .join("System32")
        .join(relative)
}

#[cfg(windows)]
fn windows_find_powershell_exe() -> std::path::PathBuf {
    let p0 = windows_system32_exe_path(r"WindowsPowerShell\v1.0\powershell.exe");
    if p0.exists() {
        return p0;
    }
    let p1 = windows_system32_exe_path("powershell.exe");
    if p1.exists() {
        return p1;
    }
    std::path::PathBuf::from("powershell")
}

#[cfg(windows)]
fn windows_find_diskshadow_exe() -> std::path::PathBuf {
    let p0 = windows_system32_exe_path("diskshadow.exe");
    if p0.exists() {
        return p0;
    }
    let sysroot = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .unwrap_or_else(|| "C:\\Windows".into());
    let p1 = std::path::PathBuf::from(sysroot)
        .join("Sysnative")
        .join("diskshadow.exe");
    if p1.exists() {
        return p1;
    }
    std::path::PathBuf::from("diskshadow")
}

#[cfg(windows)]
fn windows_find_vssadmin_exe() -> std::path::PathBuf {
    let p0 = windows_system32_exe_path("vssadmin.exe");
    if p0.exists() {
        return p0;
    }
    std::path::PathBuf::from("vssadmin")
}

#[cfg(windows)]
fn find_braced_guid_candidates(s: &str) -> Vec<(usize, String)> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i = i.saturating_add(1);
            continue;
        }
        let max_end = (i + 64).min(bytes.len());
        let mut j = i + 1;
        while j < max_end && bytes[j] != b'}' {
            j = j.saturating_add(1);
        }
        if j < bytes.len() && bytes[j] == b'}' {
            let candidate = &s[i..=j];
            if candidate.len() == 38 && is_braced_guid(candidate) {
                out.push((i, candidate.to_string()));
            }
        }
        i = i.saturating_add(1);
    }
    out
}

#[cfg(windows)]
fn is_braced_guid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 38 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            0 => {
                if b != b'{' {
                    return false;
                }
            }
            37 => {
                if b != b'}' {
                    return false;
                }
            }
            9 | 14 | 19 | 24 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(windows)]
fn choose_shadow_id_from_output(output: &str) -> Option<String> {
    let candidates = find_braced_guid_candidates(output);
    if candidates.is_empty() {
        return None;
    }
    for (pos, guid) in candidates {
        let start = pos.saturating_sub(32);
        let prefix = output
            .get(start..pos)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if prefix.contains(r"\\?\volume") || prefix.contains("volume") {
            continue;
        }
        return Some(guid);
    }
    find_braced_guid_candidates(output)
        .into_iter()
        .next()
        .map(|(_, g)| g)
}

#[cfg(windows)]
fn find_shadow_device_path_in_output(output: &str) -> Option<String> {
    const PREFIX: &str = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy";
    let start = output.find(PREFIX)?;
    let rest = &output[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .unwrap_or(rest.len());
    let val = rest[..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

#[cfg(windows)]
fn run_diskshadow_script(script: &str) -> std::io::Result<(std::process::ExitStatus, String)> {
    use std::process::Command;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = std::env::temp_dir().join(format!(
        "aegis_diskshadow_{}_{}.txt",
        std::process::id(),
        ts
    ));
    std::fs::write(path.as_path(), script)?;

    let out = Command::new(windows_find_diskshadow_exe())
        .args(["/s", path.to_string_lossy().as_ref()])
        .output()?;

    let _ignored = std::fs::remove_file(path.as_path());

    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    Ok((out.status, format!("{stdout}\n{stderr}")))
}

#[cfg(windows)]
fn vss_log_create_exec_failed<E: std::fmt::Display>(
    method: &str,
    drive_letter: char,
    volume: &str,
    context: &str,
    exe_path: &std::path::Path,
    error: &E,
) {
    tracing::warn!(
        drive_letter = %drive_letter,
        volume = %volume,
        context,
        exe_path = %exe_path.display(),
        error = %error,
        method,
        "vss create failed to execute"
    );
}

#[cfg(windows)]
fn vss_log_create_failed(
    method: &str,
    drive_letter: char,
    volume: &str,
    context: &str,
    exit_code: Option<i32>,
    output_trim: &str,
) {
    if output_trim.is_empty() {
        tracing::warn!(
            drive_letter = %drive_letter,
            volume = %volume,
            context,
            exit_code = ?exit_code,
            method,
            "vss create failed"
        );
    } else {
        tracing::warn!(
            drive_letter = %drive_letter,
            volume = %volume,
            context,
            exit_code = ?exit_code,
            output = %output_trim,
            method,
            "vss create failed"
        );
    }
}

#[cfg(windows)]
fn vss_snapshot_from_text_output(
    method: &str,
    drive_letter: char,
    volume: &str,
    context: &str,
    output: &str,
) -> Option<VssSnapshot> {
    let output_trim = output.trim();
    let Some(shadow_id) = choose_shadow_id_from_output(output) else {
        tracing::warn!(
            drive_letter = %drive_letter,
            volume = %volume,
            context,
            output = %output_trim,
            method,
            "vss create missing shadow_id"
        );
        return None;
    };
    let Some(device_path) = find_shadow_device_path_in_output(output) else {
        tracing::warn!(
            drive_letter = %drive_letter,
            volume = %volume,
            context,
            shadow_id = %shadow_id,
            output = %output_trim,
            method,
            "vss create missing device_path"
        );
        return None;
    };

    tracing::info!(
        drive_letter = %drive_letter,
        volume = %volume,
        context,
        shadow_id = %shadow_id,
        device_path = %device_path,
        method,
        "vss snapshot created"
    );
    Some(VssSnapshot {
        drive_letter,
        shadow_id,
        device_path,
    })
}

#[cfg(windows)]
fn create_vss_snapshot_for_drive_diskshadow(
    drive_letter: char,
    volume: &str,
    context: &str,
) -> Option<VssSnapshot> {
    let vol = normalize_volume_arg(volume);
    let diskshadow_context = "CLIENTACCESSIBLE";

    let script = format!(
        "SET CONTEXT {diskshadow_context} NOWRITERS\r\n\
         BEGIN BACKUP\r\n\
         ADD VOLUME {vol} ALIAS aegis\r\n\
         CREATE\r\n\
         END BACKUP\r\n"
    );

    let (status, output) = match run_diskshadow_script(script.as_str()) {
        Ok(v) => v,
        Err(e) => {
            vss_log_create_exec_failed(
                "diskshadow",
                drive_letter,
                volume,
                context,
                windows_find_diskshadow_exe().as_path(),
                &e,
            );
            return None;
        }
    };
    let output_trim = output.trim();
    if !status.success() {
        vss_log_create_failed(
            "diskshadow",
            drive_letter,
            volume,
            context,
            status.code(),
            output_trim,
        );
        return None;
    }

    vss_snapshot_from_text_output("diskshadow", drive_letter, volume, context, output.as_str())
}

#[cfg(windows)]
fn create_vss_snapshot_for_drive_vssadmin(
    drive_letter: char,
    volume: &str,
    context: &str,
) -> Option<VssSnapshot> {
    use std::process::Command;

    let help_out = Command::new(windows_find_vssadmin_exe()).output().ok()?;
    let help_stdout = String::from_utf8_lossy(help_out.stdout.as_slice());
    let help_stderr = String::from_utf8_lossy(help_out.stderr.as_slice());
    let help_combined = format!("{help_stdout}\n{help_stderr}");
    if !help_combined.to_ascii_lowercase().contains("create shadow") {
        return None;
    }

    let for_arg = format!("/for={drive_letter}:");
    let out = Command::new(windows_find_vssadmin_exe())
        .args(["create", "shadow", for_arg.as_str()])
        .output();
    let out = match out {
        Ok(v) => v,
        Err(e) => {
            vss_log_create_exec_failed(
                "vssadmin",
                drive_letter,
                volume,
                context,
                windows_find_vssadmin_exe().as_path(),
                &e,
            );
            return None;
        }
    };

    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    let combined = format!("{stdout}\n{stderr}");
    let output_trim = combined.trim();
    if !out.status.success() {
        vss_log_create_failed(
            "vssadmin",
            drive_letter,
            volume,
            context,
            out.status.code(),
            output_trim,
        );
        return None;
    }

    vss_snapshot_from_text_output("vssadmin", drive_letter, volume, context, combined.as_str())
}

#[cfg(windows)]
fn lookup_vss_device_object_vssadmin(shadow_id: &str) -> Option<String> {
    use std::process::Command;

    let out = Command::new(windows_find_vssadmin_exe())
        .args(["list", "shadows"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    let combined = format!("{stdout}\n{stderr}");

    let idx = combined.find(shadow_id)?;
    let window = combined.get(idx..(idx + 4096).min(combined.len()))?;
    find_shadow_device_path_in_output(window)
}

#[cfg(windows)]
fn create_vss_snapshot_for_drive_fallback(
    drive_letter: char,
    volume: &str,
    context: &str,
) -> Option<VssSnapshot> {
    if let Some(s) = create_vss_snapshot_for_drive_powershell(drive_letter, volume, context) {
        return Some(s);
    }
    if let Some(s) = create_vss_snapshot_for_drive_diskshadow(drive_letter, volume, context) {
        return Some(s);
    }
    create_vss_snapshot_for_drive_vssadmin(drive_letter, volume, context)
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
fn create_vss_snapshot_for_drive(drive_letter: char) -> Option<VssSnapshot> {
    #[allow(non_camel_case_types)]
    #[derive(serde::Deserialize)]
    struct Win32_ShadowCopy;

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

    let volume = format!("{drive_letter}:\\");
    let con = match WMIConnection::new() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, drive_letter = %drive_letter, "wmi connection failed");
            if vss_fallback_enabled_for_error(&e) {
                for context in ["ClientAccessibleWriters", "ClientAccessible"] {
                    if let Some(s) = create_vss_snapshot_for_drive_fallback(
                        drive_letter,
                        volume.as_str(),
                        context,
                    ) {
                        return Some(s);
                    }
                }
            }
            return None;
        }
    };

    for context in ["ClientAccessibleWriters", "ClientAccessible"] {
        let input = CreateInput {
            volume: volume.clone(),
            context: context.to_string(),
        };
        let out: CreateOutput = match con.exec_class_method::<Win32_ShadowCopy, _>("Create", input)
        {
            Ok(v) => v,
            Err(e) => {
                let fallback_enabled = vss_fallback_enabled_for_error(&e);
                tracing::warn!(
                    error = %e,
                    drive_letter = %drive_letter,
                    volume = %volume,
                    context,
                    fallback_enabled,
                    "vss create wmi error"
                );
                if fallback_enabled {
                    if let Some(s) = create_vss_snapshot_for_drive_fallback(
                        drive_letter,
                        volume.as_str(),
                        context,
                    ) {
                        return Some(s);
                    }
                    tracing::warn!(
                        drive_letter = %drive_letter,
                        volume = %volume,
                        context,
                        "vss create fallback failed"
                    );
                }
                continue;
            }
        };
        if out.return_value != 0 {
            if out.return_value == 5 {
                tracing::info!(
                    drive_letter = %drive_letter,
                    volume = %volume,
                    context,
                    return_value = out.return_value,
                    "vss create context unsupported"
                );
                continue;
            }
            tracing::warn!(
                drive_letter = %drive_letter,
                volume = %volume,
                context,
                return_value = out.return_value,
                "vss create returned failure"
            );
            continue;
        }
        let Some(shadow_id) = out.shadow_id else {
            tracing::warn!(
                drive_letter = %drive_letter,
                volume = %volume,
                context,
                "vss create returned empty shadow_id"
            );
            continue;
        };

        let escaped = shadow_id.replace('\'', "''");
        let q = format!("SELECT __Path, DeviceObject FROM Win32_ShadowCopy WHERE ID='{escaped}'");
        let rows: Vec<ShadowCopyLookup> = match con.raw_query(q.as_str()) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    drive_letter = %drive_letter,
                    volume = %volume,
                    context,
                    shadow_id = %shadow_id,
                    "vss shadowcopy lookup failed"
                );
                let fallback_enabled = vss_fallback_enabled_for_error(&e);
                if fallback_enabled {
                    if let Some(device_path) =
                        lookup_vss_device_object_powershell(shadow_id.as_str())
                    {
                        tracing::info!(
                            drive_letter = %drive_letter,
                            volume = %volume,
                            context,
                            shadow_id = %shadow_id,
                            device_path = %device_path,
                            method = "powershell",
                            "vss snapshot created"
                        );
                        return Some(VssSnapshot {
                            drive_letter,
                            shadow_id,
                            device_path,
                        });
                    }
                    if let Some(device_path) = lookup_vss_device_object_vssadmin(shadow_id.as_str())
                    {
                        tracing::info!(
                            drive_letter = %drive_letter,
                            volume = %volume,
                            context,
                            shadow_id = %shadow_id,
                            device_path = %device_path,
                            method = "vssadmin",
                            "vss snapshot created"
                        );
                        return Some(VssSnapshot {
                            drive_letter,
                            shadow_id,
                            device_path,
                        });
                    }
                    tracing::warn!(
                        drive_letter = %drive_letter,
                        volume = %volume,
                        context,
                        shadow_id = %shadow_id,
                        "vss lookup fallback failed"
                    );
                }
                continue;
            }
        };
        let Some(instance) = rows.first() else {
            tracing::warn!(
                drive_letter = %drive_letter,
                volume = %volume,
                context,
                shadow_id = %shadow_id,
                "vss shadowcopy lookup returned empty result"
            );
            continue;
        };

        tracing::info!(
            drive_letter = %drive_letter,
            volume = %volume,
            context,
            shadow_id = %shadow_id,
            device_path = %instance.device_object,
            "vss snapshot created"
        );
        return Some(VssSnapshot {
            drive_letter,
            shadow_id,
            device_path: instance.device_object.clone(),
        });
    }
    None
}

#[cfg(windows)]
fn create_vss_snapshot_for_drive_powershell(
    drive_letter: char,
    volume: &str,
    context: &str,
) -> Option<VssSnapshot> {
    let Some(output) = run_powershell_vss_create_script(volume, context) else {
        tracing::warn!(
            drive_letter = %drive_letter,
            volume = %volume,
            context,
            method = "powershell",
            "vss create returned no output"
        );
        return None;
    };
    let Some((return_value, shadow_id, device_object)) =
        parse_powershell_kv_triplet(output.as_str())
    else {
        tracing::warn!(
            drive_letter = %drive_letter,
            volume = %volume,
            context,
            output = %output,
            method = "powershell",
            "vss create output parse failed"
        );
        return None;
    };
    if return_value != 0 || shadow_id.is_empty() || device_object.is_empty() {
        tracing::warn!(
            drive_letter = %drive_letter,
            volume = %volume,
            context,
            return_value,
            shadow_id = %shadow_id,
            device_object = %device_object,
            output = %output,
            method = "powershell",
            "vss create returned non-success"
        );
        return None;
    }
    tracing::info!(
        drive_letter = %drive_letter,
        volume = %volume,
        context,
        shadow_id = %shadow_id,
        device_path = %device_object,
        method = "powershell",
        "vss snapshot created"
    );
    Some(VssSnapshot {
        drive_letter,
        shadow_id,
        device_path: device_object,
    })
}

#[cfg(windows)]
fn lookup_vss_device_object_powershell(shadow_id: &str) -> Option<String> {
    use std::process::Command;

    let script = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;\
         $sid='{shadow_id}';\
         $dev='';\
         for ($i=0; $i -lt 25 -and (-not $dev); $i++) {{\
            try {{$dev=(Get-CimInstance Win32_ShadowCopy -Filter \"ID='$sid'\" | Select-Object -First 1 -ExpandProperty DeviceObject)}} catch {{}};\
            if (-not $dev) {{\
               try {{$dev=(Get-WmiObject Win32_ShadowCopy -Filter \"ID='$sid'\" | Select-Object -First 1 -ExpandProperty DeviceObject)}} catch {{}};\
            }};\
            if (-not $dev) {{ Start-Sleep -Milliseconds 200 }}\
         }};\
         \"DeviceObject=$dev\""
    );
    let out = Command::new(windows_find_powershell_exe())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Sta",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script.as_str(),
        ])
        .output();
    let out = match out {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                shadow_id = %shadow_id,
                error = %e,
                "powershell vss lookup failed to execute"
            );
            return None;
        }
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(out.stderr.as_slice());
        if !stderr.trim().is_empty() {
            tracing::warn!(shadow_id = %shadow_id, error = %stderr.trim(), "powershell vss lookup failed");
        }
        return None;
    }
    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let line = stdout.trim();
    let (_, val) = line.split_once("DeviceObject=")?;
    let val = val.trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

#[cfg(windows)]
fn build_powershell_vss_create_script(volume: &str, context: &str) -> String {
    format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;\
         $ErrorActionPreference='Stop';\
         $vol='{volume}';\
         $ctx='{context}';\
         $rv=[uint32]1;\
         $sid='';\
         $dev='';\
         $errCim='';\
         $hrCim='';\
         $fqCim='';\
         $errWmi='';\
         $hrWmi='';\
         $fqWmi='';\
         $m='';\
         $r=$null;\
         try {{\
            $m='cim';\
            $r=Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{{Volume=$vol;Context=$ctx}} -ErrorAction Stop;\
         }} catch {{\
            $errCim=[string]$_.Exception.Message;\
            $hrCim=[string]$_.Exception.HResult;\
            $fqCim=[string]$_.FullyQualifiedErrorId;\
         }};\
         if (-not $r) {{\
            try {{\
               $m='wmi';\
               $r=([WMIClass]'Win32_ShadowCopy').Create($vol,$ctx);\
            }} catch {{\
               $errWmi=[string]$_.Exception.Message;\
               $hrWmi=[string]$_.Exception.HResult;\
               $fqWmi=[string]$_.FullyQualifiedErrorId;\
            }}\
         }};\
         if ($r) {{\
            $rv=[uint32]$r.ReturnValue;\
            $sid=[string]$r.ShadowID;\
         }} else {{\
            if (-not $errCim -and -not $errWmi) {{$errWmi='Win32_ShadowCopy.Create returned null'}}\
         }};\
         if ($rv -eq 0 -and $sid) {{\
            for ($i=0; $i -lt 25 -and (-not $dev); $i++) {{\
               try {{$dev=(Get-CimInstance Win32_ShadowCopy -Filter \"ID='$sid'\" | Select-Object -First 1 -ExpandProperty DeviceObject)}} catch {{}};\
               if (-not $dev) {{\
                  try {{$dev=(Get-WmiObject Win32_ShadowCopy -Filter \"ID='$sid'\" | Select-Object -First 1 -ExpandProperty DeviceObject)}} catch {{}};\
               }};\
               if (-not $dev) {{ Start-Sleep -Milliseconds 200 }}\
            }}\
         }};\
         $errCim=($errCim -replace ';', ',' -replace \"\\r|\\n\", ' ').Trim();\
         $hrCim=($hrCim -replace ';', ',' -replace \"\\r|\\n\", ' ').Trim();\
         $fqCim=($fqCim -replace ';', ',' -replace \"\\r|\\n\", ' ').Trim();\
         $errWmi=($errWmi -replace ';', ',' -replace \"\\r|\\n\", ' ').Trim();\
         $hrWmi=($hrWmi -replace ';', ',' -replace \"\\r|\\n\", ' ').Trim();\
         $fqWmi=($fqWmi -replace ';', ',' -replace \"\\r|\\n\", ' ').Trim();\
         \"ReturnValue=$rv;ShadowID=$sid;DeviceObject=$dev;ErrCim=$errCim;HRCim=$hrCim;FqCim=$fqCim;ErrWmi=$errWmi;HRWmi=$hrWmi;FqWmi=$fqWmi;Method=$m\""
    )
}

#[cfg(windows)]
fn run_powershell_vss_create_script(volume: &str, context: &str) -> Option<String> {
    use std::process::Command;

    let script = build_powershell_vss_create_script(volume, context);

    let out = Command::new(windows_find_powershell_exe())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Sta",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script.as_str(),
        ])
        .output();
    let out = match out {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                volume = %volume,
                context,
                error = %e,
                "powershell vss create failed to execute"
            );
            return None;
        }
    };

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(out.stderr.as_slice());
        if !stderr.trim().is_empty() {
            tracing::warn!(volume = %volume, context, error = %stderr.trim(), "powershell vss create failed");
        }
        return None;
    }

    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let line = stdout.trim();
    if line.is_empty() {
        let stderr = String::from_utf8_lossy(out.stderr.as_slice());
        let stderr = stderr.trim();
        if stderr.is_empty() {
            tracing::warn!(
                volume = %volume,
                context,
                method = "powershell",
                "vss create returned empty output"
            );
        } else {
            tracing::warn!(
                volume = %volume,
                context,
                error = %stderr,
                method = "powershell",
                "vss create returned empty output"
            );
        }
        None
    } else {
        Some(line.to_string())
    }
}

#[cfg(windows)]
fn parse_powershell_kv_triplet(line: &str) -> Option<(u32, String, String)> {
    let mut return_value: Option<u32> = None;
    let mut shadow_id: Option<String> = None;
    let mut device_object: Option<String> = None;

    for part in line.trim().split(';') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        match k {
            "ReturnValue" => return_value = v.parse::<u32>().ok(),
            "ShadowID" => shadow_id = Some(v.to_string()),
            "DeviceObject" => device_object = Some(v.to_string()),
            _ => {}
        }
    }

    Some((
        return_value?,
        shadow_id.unwrap_or_default(),
        device_object.unwrap_or_default(),
    ))
}

fn maybe_emit_telemetry(
    state: &mut LoopState,
    cfg: &common::config::AegisConfig,
    governor: &mut Governor,
    bus_tx: &EventBusTx,
    cpu_usage_percent: u32,
) {
    let interval_sec = effective_telemetry_interval_sec(cfg);
    if state.last_telemetry.elapsed() < Duration::from_secs(interval_sec) {
        return;
    }

    let interval = state.last_telemetry.elapsed();
    let governor_dropped = governor.dropped_events();
    let loop_dropped = state.dropped_counter.total();
    #[cfg(target_os = "linux")]
    let ringbuf_dropped = common::collectors::linux::read_ringbuf_dropped_events_best_effort(
        governor,
        cfg.security.ebpf_pin_dir.as_deref(),
    );
    #[cfg(not(target_os = "linux"))]
    let ringbuf_dropped = 0u64;
    let dropped_events_count = governor_dropped
        .saturating_add(loop_dropped)
        .saturating_add(ringbuf_dropped);

    let dropped_delta = dropped_events_count.saturating_sub(state.last_dropped_total);
    let mut dropped_rate_percent: u32 = 0;
    let mut overloaded: bool = false;
    if let Some(drop_rate_percent) = compute_drop_rate_percent(
        dropped_delta,
        interval,
        cfg.governor.effective_tokens_per_sec(),
    ) {
        dropped_rate_percent = drop_rate_percent;
        if drop_rate_percent > 1 {
            state.overload_streak = state.overload_streak.saturating_add(1);
        } else {
            state.overload_streak = 0;
        }
        if state.overload_streak >= 2 {
            overloaded = true;
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
        dropped_governor: governor_dropped,
        dropped_loop: loop_dropped,
        dropped_ringbuf: ringbuf_dropped,
        dropped_rate_percent,
        overloaded,
    };
    tracing::info!(
        telemetry_timestamp = telemetry.timestamp,
        cpu_usage_percent = telemetry.cpu_usage_percent,
        memory_usage_mb = telemetry.memory_usage_mb,
        dropped_governor = governor_dropped,
        dropped_loop = loop_dropped,
        dropped_ringbuf = ringbuf_dropped,
        dropped_events_count = telemetry.dropped_events_count,
        "agent telemetry"
    );
    enqueue_payload(
        bus_tx,
        Some(&state.dropped_counter),
        PayloadEnvelope::agent_telemetry(telemetry).encode_to_vec(),
    );
    if bus_tx.send(EncryptorCommand::Flush).is_err() {
        state.dropped_counter.add(1);
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

fn maybe_emit_linux_kernel_forensics_evidence(
    state: &mut LoopState,
    governor: &mut Governor,
    bus_tx: &EventBusTx,
) {
    #[cfg(target_os = "linux")]
    {
        if state.last_linux_kernel_forensics.elapsed() < Duration::from_secs(300) {
            return;
        }
        if !governor.try_consume_budget(1) {
            return;
        }

        let core_pattern =
            common::collectors::linux::read_core_pattern_best_effort(governor).unwrap_or_default();
        let core_pattern_suspicious =
            common::collectors::linux::is_core_pattern_suspicious(core_pattern.as_str());
        let hidden_kernel_modules =
            common::collectors::linux::list_hidden_kernel_modules_best_effort(governor, 64);
        let ftrace_enabled_functions =
            common::collectors::linux::read_ftrace_enabled_functions_best_effort(governor, 64);

        let mut vdso_hashes: Vec<LinuxVdsoHash> = Vec::new();
        let pids = common::collectors::linux::list_proc_pids(128);
        for pid in pids.into_iter().take(16) {
            if !governor.try_consume_budget(1) {
                break;
            }
            let exec_id = common::collectors::linux::collect_process_info_for_pid(
                pid,
                &state.process_exec_id_counter,
            )
            .exec_id;
            let Some(sha256) =
                common::collectors::linux::read_vdso_sha256_best_effort(governor, pid)
            else {
                continue;
            };
            vdso_hashes.push(LinuxVdsoHash {
                pid,
                exec_id,
                sha256: sha256.to_vec(),
            });
        }

        let evidence = LinuxKernelForensicsEvidence {
            collected_at: unix_timestamp_now(),
            core_pattern,
            core_pattern_suspicious,
            hidden_kernel_modules,
            ftrace_enabled_functions,
            vdso_hashes,
        };
        enqueue_payload(
            bus_tx,
            Some(&state.dropped_counter),
            PayloadEnvelope::linux_kernel_forensics_evidence(evidence).encode_to_vec(),
        );
        if bus_tx.send(EncryptorCommand::Flush).is_err() {
            state.dropped_counter.add(1);
            tracing::warn!("encryptor channel closed");
        }

        state.last_linux_kernel_forensics = Instant::now();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, governor, bus_tx);
    }
}

fn collect_process_snapshot(
    governor: &mut Governor,
    exec_id_counter: &std::sync::atomic::AtomicU64,
    ebpf_pin_dir: Option<&str>,
    limit: usize,
) -> Vec<ProcessInfo> {
    #[cfg(windows)]
    {
        let _ = ebpf_pin_dir;
        common::collectors::windows::collect_process_infos_governed(
            Some(governor),
            limit,
            exec_id_counter,
        )
    }
    #[cfg(target_os = "linux")]
    {
        collect_process_snapshot_linux_multiview(governor, exec_id_counter, ebpf_pin_dir, limit)
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        let _ = (governor, exec_id_counter, ebpf_pin_dir, limit);
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn collect_process_snapshot_linux_multiview(
    governor: &mut Governor,
    exec_id_counter: &std::sync::atomic::AtomicU64,
    ebpf_pin_dir: Option<&str>,
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

    match common::collectors::linux::open_aegis_exec_id_map_best_effort(governor, ebpf_pin_dir) {
        Ok(Some(map_fd)) => {
            for info in &mut out {
                if !governor.try_consume_budget(1) {
                    break;
                }
                match common::collectors::linux::lookup_aegis_exec_id_best_effort(
                    governor, &map_fd, info.pid,
                ) {
                    Ok(Some(v)) => {
                        info.exec_id = v;
                        info.exec_id_quality = "linux:ebpf_exec_id_map".to_string();
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "lookup exec_id map failed");
                        break;
                    }
                }
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "open exec_id map failed"),
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
    tmp_path: PathBuf,
    final_path: PathBuf,
    file: File,
    mac: Option<HmacSha256>,
    session_key: [u8; 32],
}

fn throttle_io_sleep(io: &mut IoLimiter, bytes: u64) {
    let sleep = io.reserve(bytes);
    if sleep > Duration::from_secs(0) {
        thread::sleep(sleep);
    }
}

impl OpenArtifactSegment {
    fn open_new(
        out_dir: &Path,
        segment_id: u64,
        org_public_key: &RsaPublicKey,
        org_key_fp: u64,
        uuid_mode: &str,
        user_passphrase: Option<&str>,
        io: &mut IoLimiter,
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
        let final_path = out_dir.join(format!("probe_{ts}_{segment_id}.aes"));
        let tmp_path = out_dir.join(format!("probe_{ts}_{segment_id}.aes.part"));
        let mut file = File::create(tmp_path.as_path())
            .map_err(|e| format!("创建 artifact 文件失败（{}）: {e}", tmp_path.display()))?;

        let mut mac = HmacSha256::new_from_slice(&session_key)
            .map_err(|_| "初始化 HMAC 失败（SessionKey 长度必须为 32 bytes）".to_string())?;
        mac.update(crypto::HMAC_SIG_LABEL_V1);

        file.write_all(header.as_slice())
            .map_err(|e| format!("写入 Header 失败: {e}"))?;
        throttle_io_sleep(io, u64::try_from(header.len()).unwrap_or(u64::MAX));
        mac.update(header.as_slice());

        let user_slot = user_passphrase
            .map(|p| encrypt_session_key_user_slot(p, &kdf_salt, &session_key))
            .transpose()?
            .unwrap_or([0u8; USER_SLOT_LEN]);
        file.write_all(user_slot.as_slice())
            .map_err(|e| format!("写入 UserSlot 失败: {e}"))?;
        throttle_io_sleep(io, u64::try_from(user_slot.len()).unwrap_or(u64::MAX));
        mac.update(user_slot.as_slice());

        file.write_all(rsa_ct.as_slice())
            .map_err(|e| format!("写入 OrgSlot 失败: {e}"))?;
        throttle_io_sleep(io, u64::try_from(rsa_ct.len()).unwrap_or(u64::MAX));
        mac.update(rsa_ct.as_slice());

        Ok(Self {
            tmp_path,
            final_path,
            file,
            mac: Some(mac),
            session_key,
        })
    }

    fn write_encrypted_chunk(
        &mut self,
        io: &mut IoLimiter,
        plaintext: &[u8],
    ) -> Result<(), common::error::AegisError> {
        let encrypted = crypto::encrypt(plaintext, self.session_key.as_slice())?;
        self.file
            .write_all(encrypted.as_slice())
            .map_err(common::error::AegisError::IoError)?;
        throttle_io_sleep(io, u64::try_from(encrypted.len()).unwrap_or(u64::MAX));
        if let Some(mac) = self.mac.as_mut() {
            mac.update(encrypted.as_slice());
        }
        Ok(())
    }

    fn finalize_and_close(mut self, io: &mut IoLimiter) -> Result<PathBuf, String> {
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
        throttle_io_sleep(io, u64::try_from(trailer.len()).unwrap_or(u64::MAX));

        let _sync_err = self.file.sync_all();
        drop(self.file);

        std::fs::rename(self.tmp_path.as_path(), self.final_path.as_path()).map_err(|e| {
            format!(
                "落盘 artifact 失败（rename {} -> {}）: {e}",
                self.tmp_path.display(),
                self.final_path.display()
            )
        })?;

        Ok(self.final_path)
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
    io_limit_mb: u32,
    artifact_cfg: ArtifactConfig,
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
            io_limit_mb,
            artifact_cfg,
        );
    });
    tx
}

#[allow(clippy::too_many_arguments)]
fn encryptor_loop(
    rx: &mpsc::Receiver<EncryptorCommand>,
    out_dir: &Path,
    org_public_key: &RsaPublicKey,
    org_key_fp: u64,
    uuid_mode: &str,
    user_passphrase: Option<&str>,
    io_limit_mb: u32,
    mut artifact_cfg: ArtifactConfig,
) {
    let mut segment_id: u64 = 0;
    let mut segment: Option<OpenArtifactSegment> = None;
    let mut io = IoLimiter::new(io_limit_mb, Instant::now());

    loop {
        let Ok(cmd) = rx.recv() else {
            flush_segment(
                &mut segment_id,
                &mut segment,
                &mut io,
                out_dir,
                &artifact_cfg,
            );
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
                        &mut io,
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
                                if s.write_encrypted_chunk(
                                    &mut io,
                                    system_info.encode_to_vec().as_slice(),
                                )
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
                    && let Err(e) = s.write_encrypted_chunk(&mut io, plaintext.as_slice())
                {
                    tracing::warn!(error = %e, "encrypt/write chunk failed");
                }
            }
            EncryptorCommand::Flush => {
                flush_segment(
                    &mut segment_id,
                    &mut segment,
                    &mut io,
                    out_dir,
                    &artifact_cfg,
                );
            }
            EncryptorCommand::UpdateIoLimitMb(mb) => {
                io.update_limit(mb);
            }
            EncryptorCommand::UpdateArtifactConfig(cfg) => {
                artifact_cfg = cfg;
            }
        }
    }
}

struct ArtifactEntry {
    path: PathBuf,
    modified: SystemTime,
    size: u64,
}

fn flush_segment(
    segment_id: &mut u64,
    segment: &mut Option<OpenArtifactSegment>,
    io: &mut IoLimiter,
    out_dir: &Path,
    artifact_cfg: &ArtifactConfig,
) {
    let Some(s) = segment.take() else {
        return;
    };

    match s.finalize_and_close(io) {
        Ok(path) => {
            tracing::info!(path = %path.display(), "artifact segment flushed");
            *segment_id = segment_id.saturating_add(1);
            cleanup_artifacts_best_effort(out_dir, artifact_cfg);
        }
        Err(e) => tracing::warn!(error = %e, "finalize artifact segment failed"),
    }
}

fn cleanup_artifacts_best_effort(out_dir: &Path, cfg: &ArtifactConfig) {
    let max_files = usize::try_from(cfg.max_files).unwrap_or(usize::MAX);
    let max_total_bytes = cfg.max_total_mb.saturating_mul(1024).saturating_mul(1024);

    if max_total_bytes == 0 && max_files == usize::MAX {
        return;
    }

    let Ok(rd) = std::fs::read_dir(out_dir) else {
        return;
    };

    let mut entries: Vec<ArtifactEntry> = Vec::new();
    for e in rd.flatten() {
        let path = e.path();
        let Some(name) = path.file_name().and_then(|v| v.to_str()) else {
            continue;
        };
        if !name.starts_with("probe_") {
            continue;
        }
        if !path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("aes"))
        {
            continue;
        }
        let Ok(meta) = e.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        entries.push(ArtifactEntry {
            path,
            modified,
            size: meta.len(),
        });
    }

    if entries.is_empty() {
        return;
    }

    entries.sort_by_key(|e| e.modified);
    let mut total_bytes: u64 = entries.iter().map(|e| e.size).sum();
    let mut deleted_files: u64 = 0;
    let mut deleted_bytes: u64 = 0;

    while (max_total_bytes != 0 && total_bytes > max_total_bytes) || entries.len() > max_files {
        let Some(e) = entries.first() else {
            break;
        };
        let path = e.path.clone();
        let size = e.size;
        entries.remove(0);
        if std::fs::remove_file(path.as_path()).is_ok() {
            deleted_files = deleted_files.saturating_add(1);
            deleted_bytes = deleted_bytes.saturating_add(size);
            total_bytes = total_bytes.saturating_sub(size);
        }
    }

    if deleted_files != 0 {
        tracing::info!(
            deleted_files,
            deleted_bytes,
            remaining_files = entries.len(),
            remaining_bytes = total_bytes,
            "artifact retention applied"
        );
    }
}

#[cfg(target_os = "linux")]
fn maybe_attach_aegis_ebpf_best_effort(
    state: &mut LoopState,
    governor: &mut Governor,
    security: &common::config::SecurityConfig,
) {
    if state.ebpf_producer.is_some() {
        return;
    }
    if state.last_ebpf_attach_attempt.elapsed() < Duration::from_secs(30) {
        return;
    }
    state.last_ebpf_attach_attempt = Instant::now();
    match common::collectors::linux::load_and_attach_aegis_ebpf_best_effort(
        governor,
        security.ebpf_object_path.as_deref(),
        security.ebpf_bpftool_path.as_deref(),
        security.ebpf_pin_dir.as_deref(),
    ) {
        Ok(Some(p)) => {
            state.ebpf_producer = Some(p);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "attach eBPF failed");
            state.dropped_counter.add(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn maybe_attach_aegis_ebpf_best_effort(
    _state: &mut LoopState,
    _governor: &mut Governor,
    _security: &common::config::SecurityConfig,
) {
}

#[allow(clippy::too_many_lines)]
fn maybe_emit_linux_ebpf_events(
    state: &mut LoopState,
    governor: &mut Governor,
    security: &common::config::SecurityConfig,
    bus_tx: &EventBusTx,
) {
    #[cfg(target_os = "linux")]
    {
        if state.last_ebpf_poll.elapsed() < Duration::from_millis(500) {
            return;
        }

        if state.ebpf_ringbuf.is_none() {
            if state.last_ebpf_open_attempt.elapsed() < Duration::from_secs(30) {
                state.last_ebpf_poll = Instant::now();
                return;
            }
            state.last_ebpf_open_attempt = Instant::now();
            match common::collectors::linux::open_aegis_ringbuf_best_effort(
                governor,
                security.ebpf_pin_dir.as_deref(),
            ) {
                Ok(Some(rb)) => state.ebpf_ringbuf = Some(rb),
                Ok(None) => {
                    state.last_ebpf_poll = Instant::now();
                    return;
                }
                Err(e) => {
                    match &e {
                        common::AegisError::ProtocolError {
                            code: Some(code), ..
                        }
                        | common::AegisError::CryptoError {
                            code: Some(code), ..
                        } => {
                            tracing::warn!(error = %e, code = %code, "open ringbuf failed");
                        }
                        _ => {
                            tracing::warn!(error = %e, "open ringbuf failed");
                        }
                    }
                    state.dropped_counter.add(1);
                    state.last_ebpf_poll = Instant::now();
                    return;
                }
            }
        }

        let Some(rb) = state.ebpf_ringbuf.as_mut() else {
            state.last_ebpf_poll = Instant::now();
            return;
        };

        let drained = match rb.drain_events_best_effort(governor, 256, 512 * 1024) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "drain ringbuf failed");
                state.last_ebpf_poll = Instant::now();
                return;
            }
        };

        if !drained.events.is_empty() {
            if state.ebpf_exec_id_map.is_none()
                && state.last_ebpf_exec_id_open_attempt.elapsed() >= Duration::from_secs(30)
            {
                state.last_ebpf_exec_id_open_attempt = Instant::now();
                match common::collectors::linux::open_aegis_exec_id_map_best_effort(
                    governor,
                    security.ebpf_pin_dir.as_deref(),
                ) {
                    Ok(Some(fd)) => state.ebpf_exec_id_map = Some(fd),
                    Ok(None) => {}
                    Err(e) => tracing::warn!(error = %e, "open exec_id map failed"),
                }
            }

            let mut events = drained.events;
            if let Some(map_fd) = state.ebpf_exec_id_map.as_ref() {
                for ev in &mut events {
                    if ev.exec_id != 0 {
                        continue;
                    }
                    if !governor.try_consume_budget(1) {
                        break;
                    }
                    match common::collectors::linux::lookup_aegis_exec_id_best_effort(
                        governor, map_fd, ev.tgid,
                    ) {
                        Ok(Some(v)) => ev.exec_id = v,
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "lookup exec_id map failed");
                            break;
                        }
                    }
                }
            }

            emit_smart_reflex_from_ebpf_events_best_effort(
                state,
                governor,
                bus_tx,
                events.as_slice(),
            );
            let dropped_total = common::collectors::linux::read_ringbuf_dropped_events_best_effort(
                governor,
                security.ebpf_pin_dir.as_deref(),
            );
            let batch = EbpfEventBatch {
                collected_at: unix_timestamp_now(),
                dropped_total,
                events,
            };
            enqueue_payload(
                bus_tx,
                Some(&state.dropped_counter),
                PayloadEnvelope::ebpf_event_batch(batch).encode_to_vec(),
            );
            if bus_tx.send(EncryptorCommand::Flush).is_err() {
                state.dropped_counter.add(1);
                tracing::warn!("encryptor channel closed");
            }
        }

        state.last_ebpf_poll = Instant::now();
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state, governor, security, bus_tx);
    }
}

fn enqueue_payload(tx: &EventBusTx, dropped: Option<&DroppedEventCounter>, bytes: Vec<u8>) {
    if tx.send(EncryptorCommand::Payload(bytes)).is_err() {
        if let Some(c) = dropped {
            c.add(1);
        }
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
    sign_plugin: Option<SignPluginArgs>,
    native_plugin_worker: Option<NativePluginWorkerArgs>,
}

#[derive(Debug)]
struct SignPluginArgs {
    key_pem: PathBuf,
    input_file: PathBuf,
    sig_out: PathBuf,
}

#[derive(Debug)]
struct NativePluginWorkerArgs {
    plugin_path: PathBuf,
    org_pubkey_der_b64: String,
    sig_mode: String,
}

#[allow(clippy::too_many_lines)]
fn parse_args<I>(mut it: I) -> Result<ProbeArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut config_path: Option<PathBuf> = None;
    let mut org_key_path: Option<PathBuf> = None;
    let mut user_passphrase: Option<String> = None;
    let mut sign_plugin = false;
    let mut sign_key_path: Option<PathBuf> = None;
    let mut sign_input_path: Option<PathBuf> = None;
    let mut sign_out_path: Option<PathBuf> = None;
    let mut native_plugin_worker = false;
    let mut worker_plugin_path: Option<PathBuf> = None;
    let mut worker_org_pubkey_der_b64: Option<String> = None;
    let mut worker_sig_mode: Option<String> = None;

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
            "--sign-plugin" => {
                sign_plugin = true;
            }
            "--key" => {
                let val = it.next().ok_or("--key 缺少参数".to_string())?;
                sign_key_path = Some(PathBuf::from(val));
            }
            "--input" => {
                let val = it.next().ok_or("--input 缺少参数".to_string())?;
                sign_input_path = Some(PathBuf::from(val));
            }
            "--out" => {
                let val = it.next().ok_or("--out 缺少参数".to_string())?;
                sign_out_path = Some(PathBuf::from(val));
            }
            "--native-plugin-worker" => {
                native_plugin_worker = true;
            }
            "--plugin" => {
                let val = it.next().ok_or("--plugin 缺少参数".to_string())?;
                worker_plugin_path = Some(PathBuf::from(val));
            }
            "--org-pubkey-der-b64" => {
                let val = it
                    .next()
                    .ok_or("--org-pubkey-der-b64 缺少参数".to_string())?;
                worker_org_pubkey_der_b64 = Some(val);
            }
            "--sig-mode" => {
                let val = it.next().ok_or("--sig-mode 缺少参数".to_string())?;
                worker_sig_mode = Some(val);
            }
            "--help" | "-h" => {
                return Err(
                    "Usage:\n  probe --config <FILE> [--org-key-path <FILE>] [--user-passphrase <TEXT>]\n  probe --sign-plugin --key <PEM> --input <DLL/SO> [--out <SIG>]\n"
                        .to_string(),
                );
            }
            other => return Err(format!("未知参数: {other}")),
        }
    }

    let sign_plugin = if sign_plugin {
        let key_pem = sign_key_path.ok_or("--sign-plugin 需要 --key <PEM>".to_string())?;
        let input_file = sign_input_path.ok_or("--sign-plugin 需要 --input <FILE>".to_string())?;
        let sig_out = if let Some(p) = sign_out_path {
            p
        } else {
            let fname = input_file
                .file_name()
                .and_then(|f| f.to_str())
                .ok_or_else(|| format!("input 路径缺少文件名: {}", input_file.display()))?;
            input_file.with_file_name(format!("{fname}.sig"))
        };
        Some(SignPluginArgs {
            key_pem,
            input_file,
            sig_out,
        })
    } else {
        None
    };

    let native_plugin_worker = if native_plugin_worker {
        let plugin_path =
            worker_plugin_path.ok_or("--native-plugin-worker 需要 --plugin <FILE>".to_string())?;
        let org_pubkey_der_b64 = worker_org_pubkey_der_b64
            .ok_or("--native-plugin-worker 需要 --org-pubkey-der-b64 <B64>".to_string())?;
        let sig_mode =
            worker_sig_mode.ok_or("--native-plugin-worker 需要 --sig-mode <MODE>".to_string())?;
        Some(NativePluginWorkerArgs {
            plugin_path,
            org_pubkey_der_b64,
            sig_mode,
        })
    } else {
        None
    };

    Ok(ProbeArgs {
        config_path,
        org_key_path,
        user_passphrase,
        sign_plugin,
        native_plugin_worker,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::cim_datetime_to_unix_seconds;
    use super::{
        EncryptorCommand, LoopState, OpenArtifactSegment, PluginManager, USER_SLOT_LEN,
        compute_drop_rate_percent, effective_telemetry_interval_sec, encryptor_loop, parse_args,
        validate_key_requirements,
    };
    use common::config::ArtifactConfig;
    use common::config::{GovernorConfig, TokenBucketConfig};
    use common::crypto;
    use common::governor::Governor;
    use common::governor::IoLimiter;
    use common::protocol::{PayloadEnvelope, ProcessInfo, payload_envelope};
    use prost::Message;
    use rand::rngs::OsRng;
    use rsa::Oaep;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::traits::PublicKeyParts;
    use sha2::Sha256;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

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
    fn parse_args_parses_all_flags() -> Result<(), String> {
        let args = parse_args(
            vec![
                "--config",
                "c.yaml",
                "--org-key-path",
                "k.der",
                "--user-passphrase",
                "pw",
            ]
            .into_iter()
            .map(str::to_string),
        )?;
        assert_eq!(args.config_path, Some(PathBuf::from("c.yaml")));
        assert_eq!(args.org_key_path, Some(PathBuf::from("k.der")));
        assert_eq!(args.user_passphrase, Some("pw".to_string()));
        Ok(())
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let err = parse_args(vec!["--wat"].into_iter().map(str::to_string))
            .err()
            .unwrap_or_default();
        assert!(err.contains("未知参数"));
    }

    #[test]
    fn parse_args_rejects_missing_value() {
        let err = parse_args(vec!["--config"].into_iter().map(str::to_string))
            .err()
            .unwrap_or_default();
        assert!(err.contains("--config 缺少参数"));
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

    #[test]
    fn process_snapshot_does_not_reset_timestamp_when_budget_insufficient() {
        let (bus_tx, _bus_rx) = tokio::sync::mpsc::unbounded_channel();

        let governor_cfg = GovernorConfig {
            token_bucket: TokenBucketConfig {
                capacity: 1,
                refill_per_sec: 1,
            },
            max_single_core_usage: 100,
            net_packet_limit_per_sec: 0,
            io_limit_mb: 0,
            ..GovernorConfig::default()
        };
        let mut governor = Governor::new(&governor_cfg);
        assert!(governor.try_consume_budget(1));
        assert!(!governor.try_consume_budget(1));

        let base_dir = PathBuf::from(".");
        let mut state = LoopState::new(base_dir.as_path());
        let now = Instant::now();
        let old = now.checked_sub(Duration::from_secs(61)).unwrap_or(now);
        state.last_process_snapshot = old;

        let plugins = PluginManager {
            wasm: None,
            native: Vec::new(),
        };
        let cfg = common::config::AegisConfig::default();
        super::maybe_emit_process_snapshot(&mut state, &mut governor, &cfg, &plugins, &bus_tx);

        assert_eq!(state.last_process_snapshot, old);
        assert_eq!(governor.dropped_events(), 2);
    }

    #[test]
    fn network_update_does_not_reset_timestamp_when_budget_insufficient() {
        let (bus_tx, _bus_rx) = tokio::sync::mpsc::unbounded_channel();

        let governor_cfg = GovernorConfig {
            token_bucket: TokenBucketConfig {
                capacity: 1,
                refill_per_sec: 1,
            },
            max_single_core_usage: 100,
            net_packet_limit_per_sec: 0,
            io_limit_mb: 0,
            ..GovernorConfig::default()
        };
        let mut governor = Governor::new(&governor_cfg);
        assert!(governor.try_consume_budget(1));
        assert!(!governor.try_consume_budget(1));

        let base_dir = PathBuf::from(".");
        let mut state = LoopState::new(base_dir.as_path());
        let now = Instant::now();
        let old = now.checked_sub(Duration::from_secs(61)).unwrap_or(now);
        state.last_network_snapshot = old;

        super::maybe_emit_network_update(&mut state, &mut governor, &bus_tx);

        assert_eq!(state.last_network_snapshot, old);
        assert_eq!(governor.dropped_events(), 2);
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
    fn encryptor_inserts_system_info_when_first_payload_is_not_system_info() -> Result<(), String> {
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
            "aegis_probe_encryptor_test_{}_{}",
            std::process::id(),
            super::unix_timestamp_now()
        ));
        std::fs::create_dir_all(dir.as_path())
            .map_err(|e| format!("创建临时目录失败（{}）: {e}", dir.display()))?;

        let (tx, rx) = mpsc::channel::<EncryptorCommand>();
        let out_dir = dir.clone();
        let t = thread::spawn(move || {
            encryptor_loop(
                &rx,
                out_dir.as_path(),
                &public_key,
                org_key_fp,
                "dev",
                Some("aegis-dev"),
                0,
                ArtifactConfig::default(),
            );
        });

        let proc_payload = PayloadEnvelope::process_info(ProcessInfo {
            pid: 123,
            ppid: 0,
            name: "p".to_string(),
            cmdline: "p".to_string(),
            exe_path: "C:\\p.exe".to_string(),
            uid: 0,
            start_time: 1,
            is_ghost: false,
            is_mismatched: false,
            has_floating_code: false,
            exec_id: 1,
            exec_id_quality: "test".to_string(),
        })
        .encode_to_vec();

        tx.send(EncryptorCommand::Payload(proc_payload))
            .map_err(|e| format!("发送 payload 失败: {e}"))?;
        drop(tx);
        t.join()
            .map_err(|_| "等待 encryptor 线程失败".to_string())?;

        let mut aes_files: Vec<PathBuf> = std::fs::read_dir(dir.as_path())
            .map_err(|e| format!("读取临时目录失败（{}）: {e}", dir.display()))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "aes"))
            .collect();
        aes_files.sort();
        let path = aes_files
            .first()
            .ok_or("未生成 artifact 文件".to_string())?;

        let bytes = std::fs::read(path.as_path())
            .map_err(|e| format!("读取 artifact 文件失败（{}）: {e}", path.display()))?;

        let rsa_ct_len = private_key.size();
        let rsa_start = crypto::AES_HEADER_LEN + USER_SLOT_LEN;
        let rsa_end = rsa_start + rsa_ct_len;
        let rsa_ct = bytes
            .get(rsa_start..rsa_end)
            .ok_or("读取 OrgSlot 失败".to_string())?;
        let stream = bytes.get(rsa_end..).ok_or("读取 stream 失败".to_string())?;

        let session_key_bytes = private_key
            .decrypt(Oaep::new::<Sha256>(), rsa_ct)
            .map_err(|e| format!("RSA-OAEP 解密 SessionKey 失败: {e}"))?;
        let session_key: [u8; 32] = session_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "OrgSlot 解出的 SessionKey 长度异常".to_string())?;

        let plaintexts = decrypt_stream_to_plaintexts(stream, &session_key, 8)
            .map_err(|e| format!("解密 stream 失败: {e}"))?;
        let first = plaintexts.first().ok_or("缺少第一个 chunk".to_string())?;
        let second = plaintexts.get(1).ok_or("缺少第二个 chunk".to_string())?;
        let env1 = PayloadEnvelope::decode(first.as_slice())
            .map_err(|e| format!("PayloadEnvelope 反序列化失败: {e}"))?;
        let env2 = PayloadEnvelope::decode(second.as_slice())
            .map_err(|e| format!("PayloadEnvelope 反序列化失败: {e}"))?;

        assert!(matches!(
            env1.payload,
            Some(payload_envelope::Payload::SystemInfo(_))
        ));
        assert!(matches!(
            env2.payload,
            Some(payload_envelope::Payload::ProcessInfo(_))
        ));

        let _cleanup = std::fs::remove_dir_all(dir.as_path());
        Ok(())
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

        let mut io = IoLimiter::new(0, Instant::now());
        let mut seg = OpenArtifactSegment::open_new(
            dir.as_path(),
            0,
            &public_key,
            org_key_fp,
            "dev",
            Some("aegis-dev"),
            &mut io,
        )?;
        let env = PayloadEnvelope::system_info(common::protocol::SystemInfo {
            hostname: "h".to_string(),
            os_version: "o".to_string(),
            kernel_version: "k".to_string(),
            ip_addresses: Vec::new(),
            boot_time: 1,
        });
        seg.write_encrypted_chunk(&mut io, env.encode_to_vec().as_slice())
            .map_err(|e| format!("写入 payload 失败: {e}"))?;
        let path = seg.finalize_and_close(&mut io)?;

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

    fn write_console_fixture_artifact(
        dir: &std::path::Path,
        public_key: &rsa::RsaPublicKey,
        org_key_fp: u64,
        passphrase: &str,
    ) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
        let mut io = IoLimiter::new(0, Instant::now());
        let mut seg = OpenArtifactSegment::open_new(
            dir,
            0,
            public_key,
            org_key_fp,
            "dev",
            Some(passphrase),
            &mut io,
        )?;

        let sys = PayloadEnvelope::system_info(common::protocol::SystemInfo {
            hostname: "h".to_string(),
            os_version: "o".to_string(),
            kernel_version: "k".to_string(),
            ip_addresses: vec!["10.0.0.1".to_string()],
            boot_time: 1,
        })
        .encode_to_vec();
        seg.write_encrypted_chunk(&mut io, sys.as_slice())?;

        let parent = PayloadEnvelope::process_info(ProcessInfo {
            pid: 100,
            ppid: 0,
            name: "p100".to_string(),
            cmdline: "p100".to_string(),
            exe_path: "C:\\p100.exe".to_string(),
            uid: 0,
            start_time: 2_000,
            is_ghost: false,
            is_mismatched: false,
            has_floating_code: false,
            exec_id: 1,
            exec_id_quality: "windows:psn".to_string(),
        })
        .encode_to_vec();
        seg.write_encrypted_chunk(&mut io, parent.as_slice())?;

        let child = PayloadEnvelope::process_info(ProcessInfo {
            pid: 200,
            ppid: 100,
            name: "p200".to_string(),
            cmdline: "p200".to_string(),
            exe_path: "C:\\p200.exe".to_string(),
            uid: 0,
            start_time: 2_500,
            is_ghost: false,
            is_mismatched: false,
            has_floating_code: false,
            exec_id: 2,
            exec_id_quality: "windows:psn".to_string(),
        })
        .encode_to_vec();
        seg.write_encrypted_chunk(&mut io, child.as_slice())?;

        Ok(seg.finalize_and_close(&mut io)?)
    }

    fn assert_console_can_open_and_view(
        path: &std::path::Path,
        passphrase: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use console::{
            Decryption, EdgeType, GetGraphViewportInput, OpenArtifactInput, OpenArtifactOptions,
            Source, ViewportLevel,
        };

        let mut c = console::Console::new(console::ConsoleConfig {
            max_level01_nodes: 20_000,
            persistence: None,
        });
        let out = c.open_artifact(OpenArtifactInput {
            source: Source::LocalPath {
                path: path.display().to_string(),
            },
            decryption: Decryption::UserPassphrase {
                passphrase: passphrase.to_string(),
            },
            options: OpenArtifactOptions::default(),
        })?;
        assert!(out.sealed);
        assert!(!out.case_id.is_empty());
        assert!(!out.host_uuid.is_empty());
        assert!(!out.org_key_fp.is_empty());

        let v = c.get_graph_viewport(GetGraphViewportInput {
            case_id: out.case_id,
            level: ViewportLevel::L0,
            viewport_bbox: None,
            risk_score_threshold: Some(0),
            center_node_id: None,
            page: None,
        })?;
        assert!(v.nodes.len() >= 2);
        assert!(
            v.edges
                .iter()
                .any(|e| matches!(e.r#type, EdgeType::ParentOf))
        );
        Ok(())
    }

    #[test]
    fn probe_artifact_can_be_opened_by_console() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let public_key_der = public_key.to_public_key_der()?.as_bytes().to_vec();
        let org_key_fp = crypto::org_pubkey_fingerprint_xxh64(public_key_der.as_slice());

        let dir = std::env::temp_dir().join(format!(
            "aegis_probe_console_e2e_test_{}_{}",
            std::process::id(),
            crypto::org_pubkey_fingerprint_xxh64(public_key_der.as_slice())
        ));
        std::fs::create_dir_all(dir.as_path())?;

        let passphrase = "pw_console";
        let path =
            write_console_fixture_artifact(dir.as_path(), &public_key, org_key_fp, passphrase)?;
        assert_console_can_open_and_view(path.as_path(), passphrase)?;

        let _cleanup = std::fs::remove_dir_all(dir.as_path());
        Ok(())
    }
}
