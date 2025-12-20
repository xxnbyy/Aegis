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
}

impl AegisConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
        self.crypto.validate()?;
        self.governor.validate()?;
        self.security.validate()?;
        self.networking.validate()?;
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
    pub pid: PidConfig,
    pub token_bucket: TokenBucketConfig,
    pub max_single_core_usage: u32,
    #[serde(alias = "tokens_per_sec")]
    pub net_packet_limit_per_sec: u32,
    pub io_limit_mb: u32,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
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

    pub fn effective_token_bucket(&self) -> TokenBucketConfig {
        if self.net_packet_limit_per_sec == 0 {
            return self.token_bucket.clone();
        }

        if self.token_bucket != TokenBucketConfig::default() {
            return self.token_bucket.clone();
        }

        TokenBucketConfig {
            capacity: self.net_packet_limit_per_sec,
            refill_per_sec: self.net_packet_limit_per_sec,
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
    pub timestomp_threshold_ms: u64,
    pub scan_whitelist: Vec<String>,
    pub yara_rule_paths: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_native_plugins: false,
            timestomp_threshold_ms: 1000,
            scan_whitelist: Vec::new(),
            yara_rule_paths: Vec::new(),
        }
    }
}

impl SecurityConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn validate(&self) -> Result<(), AegisError> {
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
