use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::event::{CreateKind, RemoveKind};
use notify::{EventKind, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};

use crate::error::AegisError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct AegisConfig {
    pub crypto: CryptoConfig,
    pub governor: GovernorConfig,
    pub security: SecurityConfig,
    pub networking: NetworkingConfig,
    pub forensics: ForensicsConfig,
    pub artifact: ArtifactConfig,
}

impl AegisConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        self.crypto.validate()?;
        self.governor.validate()?;
        self.security.validate()?;
        self.networking.validate()?;
        self.forensics.validate()?;
        self.artifact.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WindowsMemoryScanDepth {
    #[serde(alias = "quick")]
    #[default]
    Fast,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ForensicsConfig {
    pub windows_memory_scan_depth: WindowsMemoryScanDepth,
}

impl ForensicsConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        let _ = self;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct CryptoConfig {
    pub org_key_path: Option<PathBuf>,
    pub user_passphrase: Option<String>,
}

impl CryptoConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GovernorConfig {
    #[serde(alias = "mode")]
    pub profile: GovernorProfile,
    pub pid: PidConfig,
    pub token_bucket: TokenBucketConfig,
    pub max_single_core_usage: u32,
    #[serde(alias = "tokens_per_sec")]
    pub net_packet_limit_per_sec: u32,
    pub io_limit_mb: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernorProfile {
    #[default]
    Custom,
    Office,
    War,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            profile: GovernorProfile::default(),
            pid: PidConfig::default(),
            token_bucket: TokenBucketConfig::default(),
            max_single_core_usage: 5,
            net_packet_limit_per_sec: 5000,
            io_limit_mb: 10,
        }
    }
}

impl GovernorConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        if self.max_single_core_usage > 100 {
            return Err(AegisError::ConfigError {
                message: "max_single_core_usage 不能大于 100".to_string(),
            });
        }
        self.pid.validate()?;
        self.token_bucket.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn effective_profile_applied(&self) -> Self {
        let mut cfg = self.clone();
        match self.profile {
            GovernorProfile::Custom => cfg,
            GovernorProfile::Office => {
                cfg.pid = PidConfig::default();
                cfg.token_bucket = TokenBucketConfig::default();
                cfg.max_single_core_usage = 5;
                cfg.net_packet_limit_per_sec = 5000;
                cfg.io_limit_mb = 10;
                cfg
            }
            GovernorProfile::War => {
                cfg.pid = PidConfig::default();
                cfg.token_bucket = TokenBucketConfig::default();
                cfg.max_single_core_usage = 80;
                cfg.net_packet_limit_per_sec = 50_000;
                cfg.io_limit_mb = 0;
                cfg
            }
        }
    }

    pub fn effective_token_bucket(&self) -> TokenBucketConfig {
        let cfg = self.effective_profile_applied();
        if cfg.net_packet_limit_per_sec == 0 {
            return cfg.token_bucket;
        }

        if cfg.token_bucket != TokenBucketConfig::default() {
            return cfg.token_bucket;
        }

        TokenBucketConfig {
            capacity: cfg.net_packet_limit_per_sec,
            refill_per_sec: cfg.net_packet_limit_per_sec,
        }
    }

    pub fn effective_tokens_per_sec(&self) -> u32 {
        self.effective_token_bucket().refill_per_sec
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PidConfig {
    pub k_p: f64,
    pub k_i: f64,
    pub k_d: f64,
}

impl Default for PidConfig {
    fn default() -> Self {
        Self {
            k_p: 0.8,
            k_i: 0.05,
            k_d: 0.1,
        }
    }
}

impl PidConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        if !self.k_p.is_finite() || !self.k_i.is_finite() || !self.k_d.is_finite() {
            return Err(AegisError::ConfigError {
                message: "pid 参数必须为有限数值".to_string(),
            });
        }
        if self.k_p < 0.0 || self.k_i < 0.0 || self.k_d < 0.0 {
            return Err(AegisError::ConfigError {
                message: "pid 参数不能为负数".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TokenBucketConfig {
    pub capacity: u32,
    pub refill_per_sec: u32,
}

impl Default for TokenBucketConfig {
    fn default() -> Self {
        Self {
            capacity: 10_000,
            refill_per_sec: 10_000,
        }
    }
}

impl TokenBucketConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        if self.capacity == 0 {
            return Err(AegisError::ConfigError {
                message: "token_bucket.capacity 不能为 0".to_string(),
            });
        }
        if self.refill_per_sec == 0 {
            return Err(AegisError::ConfigError {
                message: "token_bucket.refill_per_sec 不能为 0".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SecurityConfig {
    pub enable_native_plugins: bool,
    pub native_plugin_isolation: String,
    pub native_plugin_timeout_ms: u64,
    pub native_plugin_sig_mode: String,
    pub wasm_plugin_paths: Vec<String>,
    pub wasm_permissions_allow: Vec<String>,
    pub native_plugin_paths: Vec<String>,
    pub ebpf_object_path: Option<String>,
    pub ebpf_bpftool_path: Option<String>,
    pub ebpf_pin_dir: Option<String>,
    pub timestomp_threshold_ms: u64,
    pub scan_whitelist: Vec<String>,
    pub yara_rule_paths: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_native_plugins: false,
            native_plugin_isolation: "in_process".to_string(),
            native_plugin_timeout_ms: 1500,
            native_plugin_sig_mode: "hybrid".to_string(),
            wasm_plugin_paths: Vec::new(),
            wasm_permissions_allow: Vec::new(),
            native_plugin_paths: Vec::new(),
            ebpf_object_path: None,
            ebpf_bpftool_path: None,
            ebpf_pin_dir: None,
            timestomp_threshold_ms: 1000,
            scan_whitelist: Vec::new(),
            yara_rule_paths: Vec::new(),
        }
    }
}

impl SecurityConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        if self.wasm_plugin_paths.iter().any(|p| p.trim().is_empty()) {
            return Err(AegisError::ConfigError {
                message: "security.wasm_plugin_paths 不能包含空路径".to_string(),
            });
        }
        if self
            .wasm_permissions_allow
            .iter()
            .any(|p| p.trim().is_empty())
        {
            return Err(AegisError::ConfigError {
                message: "security.wasm_permissions_allow 不能包含空权限".to_string(),
            });
        }
        if self.native_plugin_paths.iter().any(|p| p.trim().is_empty()) {
            return Err(AegisError::ConfigError {
                message: "security.native_plugin_paths 不能包含空路径".to_string(),
            });
        }
        if self.native_plugin_isolation.trim().is_empty() {
            return Err(AegisError::ConfigError {
                message: "security.native_plugin_isolation 不能为空".to_string(),
            });
        }
        if !matches!(
            self.native_plugin_isolation.trim(),
            "in_process" | "subprocess"
        ) {
            return Err(AegisError::ConfigError {
                message: "security.native_plugin_isolation 仅允许 in_process/subprocess"
                    .to_string(),
            });
        }
        if self.native_plugin_timeout_ms == 0 {
            return Err(AegisError::ConfigError {
                message: "security.native_plugin_timeout_ms 不能为 0".to_string(),
            });
        }
        if self.native_plugin_sig_mode.trim().is_empty() {
            return Err(AegisError::ConfigError {
                message: "security.native_plugin_sig_mode 不能为空".to_string(),
            });
        }
        if !matches!(
            self.native_plugin_sig_mode.trim(),
            "ed25519" | "rsa_pkcs1v15" | "hybrid"
        ) {
            return Err(AegisError::ConfigError {
                message: "security.native_plugin_sig_mode 仅允许 ed25519/rsa_pkcs1v15/hybrid"
                    .to_string(),
            });
        }
        if self
            .ebpf_object_path
            .as_ref()
            .is_some_and(|p| p.trim().is_empty())
        {
            return Err(AegisError::ConfigError {
                message: "security.ebpf_object_path 不能是空字符串".to_string(),
            });
        }
        if self
            .ebpf_bpftool_path
            .as_ref()
            .is_some_and(|p| p.trim().is_empty())
        {
            return Err(AegisError::ConfigError {
                message: "security.ebpf_bpftool_path 不能是空字符串".to_string(),
            });
        }
        if self
            .ebpf_pin_dir
            .as_ref()
            .is_some_and(|p| p.trim().is_empty())
        {
            return Err(AegisError::ConfigError {
                message: "security.ebpf_pin_dir 不能是空字符串".to_string(),
            });
        }
        if self.yara_rule_paths.iter().any(|p| p.trim().is_empty()) {
            return Err(AegisError::ConfigError {
                message: "security.yara_rule_paths 不能包含空路径".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NetworkingConfig {
    pub c2_url: String,
    pub heartbeat_interval_sec: u64,
}

impl Default for NetworkingConfig {
    fn default() -> Self {
        Self {
            c2_url: String::new(),
            heartbeat_interval_sec: 60,
        }
    }
}

impl NetworkingConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        if self.heartbeat_interval_sec == 0 {
            return Err(AegisError::ConfigError {
                message: "heartbeat_interval_sec 不能为 0".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ArtifactConfig {
    pub max_files: u32,
    pub max_total_mb: u64,
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self {
            max_files: 4096,
            max_total_mb: 2048,
        }
    }
}

impl ArtifactConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        if self.max_files == 0 {
            return Err(AegisError::ConfigError {
                message: "artifact.max_files 不能为 0".to_string(),
            });
        }
        Ok(())
    }
}

pub struct ConfigManager {
    path: PathBuf,
    config: Arc<ArcSwap<AegisConfig>>,
    watcher_thread: Option<thread::JoinHandle<()>>,
    stop_tx: Option<mpsc::Sender<()>>,
}

impl ConfigManager {
    #[allow(clippy::missing_errors_doc)]
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, AegisError> {
        let path = path.into();
        let cfg = load_yaml_file(path.as_path())?;
        cfg.validate()?;
        Ok(Self {
            path,
            config: Arc::new(ArcSwap::from_pointee(cfg)),
            watcher_thread: None,
            stop_tx: None,
        })
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn from_config(path: impl Into<PathBuf>, cfg: AegisConfig) -> Result<Self, AegisError> {
        let path = path.into();
        cfg.validate()?;
        Ok(Self {
            path,
            config: Arc::new(ArcSwap::from_pointee(cfg)),
            watcher_thread: None,
            stop_tx: None,
        })
    }

    pub fn current(&self) -> Arc<AegisConfig> {
        self.config.load_full()
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn reload_now(&self) -> Result<(), AegisError> {
        let cfg = load_yaml_file(self.path.as_path())?;
        cfg.validate()?;
        self.config.store(Arc::new(cfg));
        Ok(())
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn start_watching(&mut self) -> Result<(), AegisError> {
        if self.watcher_thread.is_some() {
            return Ok(());
        }

        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::channel::<bool>();
        let path = self.path.clone();
        let watch_dir = path
            .parent()
            .map_or_else(|| PathBuf::from("."), ToOwned::to_owned);
        let store = Arc::clone(&self.config);

        let handle = thread::spawn(move || {
            let (event_tx, event_rx) = mpsc::channel();
            let Ok(mut watcher) = notify::recommended_watcher(event_tx) else {
                let _send_result = ready_tx.send(false);
                return;
            };

            if watcher
                .watch(watch_dir.as_path(), RecursiveMode::NonRecursive)
                .is_err()
            {
                let _send_result = ready_tx.send(false);
                return;
            }

            let _send_result = ready_tx.send(true);
            loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }

                let Ok(event) = event_rx.recv_timeout(Duration::from_millis(200)) else {
                    continue;
                };

                let Ok(event) = event else {
                    continue;
                };

                if !is_relevant_config_event(event.kind) {
                    continue;
                }

                thread::sleep(Duration::from_millis(25));
                if let Ok(cfg) = load_yaml_file(path.as_path())
                    && cfg.validate().is_ok()
                {
                    store.store(Arc::new(cfg));
                }
            }
        });

        if let Ok(true) = ready_rx.recv_timeout(Duration::from_secs(2)) {
        } else {
            let _send_result = stop_tx.send(());
            drop(handle.join());
            return Err(AegisError::ConfigError {
                message: "启动配置 watcher 失败".to_string(),
            });
        }

        self.watcher_thread = Some(handle);
        self.stop_tx = Some(stop_tx);
        Ok(())
    }
}

impl Drop for ConfigManager {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _send_result = tx.send(());
        }
        if let Some(handle) = self.watcher_thread.take() {
            drop(handle.join());
        }
    }
}

#[allow(clippy::missing_errors_doc)]
pub fn load_yaml_file(path: &Path) -> Result<AegisConfig, AegisError> {
    let text = std::fs::read_to_string(path).map_err(AegisError::IoError)?;
    serde_yaml::from_str::<AegisConfig>(&text).map_err(|e| AegisError::ConfigError {
        message: format!("解析配置 YAML 失败: {e}"),
    })
}

fn is_relevant_config_event(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::Modify(_)
            | EventKind::Create(CreateKind::File)
            | EventKind::Remove(RemoveKind::File)
            | EventKind::Any
    )
}

#[cfg(test)]
mod tests {
    use super::{GovernorConfig, TokenBucketConfig};

    #[test]
    fn effective_token_bucket_prefers_explicit_token_bucket() {
        let cfg = GovernorConfig {
            net_packet_limit_per_sec: 111,
            token_bucket: TokenBucketConfig {
                capacity: 222,
                refill_per_sec: 333,
            },
            ..GovernorConfig::default()
        };
        assert_eq!(cfg.effective_token_bucket(), cfg.token_bucket);
    }

    #[test]
    fn effective_token_bucket_maps_net_packet_limit_when_token_bucket_default() {
        let cfg = GovernorConfig {
            net_packet_limit_per_sec: 1234,
            token_bucket: TokenBucketConfig::default(),
            ..GovernorConfig::default()
        };
        assert_eq!(cfg.effective_token_bucket().capacity, 1234);
        assert_eq!(cfg.effective_token_bucket().refill_per_sec, 1234);
    }
}
