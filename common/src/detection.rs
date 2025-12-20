use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::event::{CreateKind, RemoveKind};
use notify::{EventKind, RecursiveMode, Watcher};

use crate::config::{AegisConfig, load_yaml_file};
use crate::error::AegisError;

pub struct RuleSet {
    timestomp_threshold_ms: u64,
    scan_whitelist: Vec<String>,
    yara_rule_paths: Vec<PathBuf>,
    yara_rules: Option<Mutex<yara::Rules>>,
}

impl RuleSet {
    pub fn timestomp_threshold_ms(&self) -> u64 {
        self.timestomp_threshold_ms
    }

    pub fn scan_whitelist(&self) -> &[String] {
        self.scan_whitelist.as_slice()
    }

    pub fn yara_rule_paths(&self) -> &[PathBuf] {
        self.yara_rule_paths.as_slice()
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn scan_mem(&self, mem: &[u8], timeout_secs: i32) -> Result<Vec<String>, AegisError> {
        let Some(mtx) = self.yara_rules.as_ref() else {
            return Ok(Vec::new());
        };

        let rules = mtx.lock().map_err(|_| AegisError::ConfigError {
            message: "YARA rules mutex poisoned".to_string(),
        })?;
        let results = rules
            .scan_mem(mem, timeout_secs)
            .map_err(|e| AegisError::ConfigError {
                message: format!("YARA scan failed: {e}"),
            })?;
        Ok(results
            .into_iter()
            .map(|m| m.identifier.to_string())
            .collect())
    }
}

pub struct RuleManager {
    config_path: PathBuf,
    rules: Arc<ArcSwap<RuleSet>>,
    watcher_thread: Option<thread::JoinHandle<()>>,
    stop_tx: Option<mpsc::Sender<()>>,
}

impl RuleManager {
    #[allow(clippy::missing_errors_doc)]
    pub fn load(config_path: impl Into<PathBuf>) -> Result<Self, AegisError> {
        let config_path = config_path.into();
        let cfg = load_yaml_file(config_path.as_path())?;
        cfg.validate()?;
        let rule_set = build_rule_set(config_path.as_path(), &cfg)?;
        Ok(Self {
            config_path,
            rules: Arc::new(ArcSwap::from_pointee(rule_set)),
            watcher_thread: None,
            stop_tx: None,
        })
    }

    pub fn current(&self) -> Arc<RuleSet> {
        self.rules.load_full()
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn reload_now(&self) -> Result<(), AegisError> {
        let cfg = load_yaml_file(self.config_path.as_path())?;
        cfg.validate()?;
        let rule_set = build_rule_set(self.config_path.as_path(), &cfg)?;
        self.rules.store(Arc::new(rule_set));
        Ok(())
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn start_watching(&mut self) -> Result<(), AegisError> {
        if self.watcher_thread.is_some() {
            return Ok(());
        }

        let cfg = load_yaml_file(self.config_path.as_path())?;
        cfg.validate()?;

        let watch_dirs = desired_watch_dirs(self.config_path.as_path(), &cfg);
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::channel::<bool>();
        let config_path = self.config_path.clone();
        let store = Arc::clone(&self.rules);

        let handle = thread::spawn(move || {
            let (event_tx, event_rx) = mpsc::channel();
            let Ok(mut watcher) = notify::recommended_watcher(event_tx) else {
                let _send_result = ready_tx.send(false);
                return;
            };

            let mut watched_dirs: BTreeSet<PathBuf> = BTreeSet::new();
            for dir in watch_dirs {
                if watcher
                    .watch(dir.as_path(), RecursiveMode::NonRecursive)
                    .is_ok()
                {
                    watched_dirs.insert(dir);
                }
            }

            if watched_dirs.is_empty() {
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
                if !is_relevant_rule_event(event.kind) {
                    continue;
                }

                thread::sleep(Duration::from_millis(25));
                let Ok(cfg) = load_yaml_file(config_path.as_path()) else {
                    continue;
                };
                if cfg.validate().is_err() {
                    continue;
                }
                let Ok(rule_set) = build_rule_set(config_path.as_path(), &cfg) else {
                    continue;
                };

                store.store(Arc::new(rule_set));

                let desired = desired_watch_dirs(config_path.as_path(), &cfg);
                let mut next: BTreeSet<PathBuf> = BTreeSet::new();

                for dir in desired {
                    if watched_dirs.contains(&dir) {
                        next.insert(dir);
                        continue;
                    }
                    if watcher
                        .watch(dir.as_path(), RecursiveMode::NonRecursive)
                        .is_ok()
                    {
                        next.insert(dir);
                    }
                }

                for old in watched_dirs {
                    if next.contains(&old) {
                        continue;
                    }
                    drop(watcher.unwatch(old.as_path()));
                }

                watched_dirs = next;
            }
        });

        if let Ok(true) = ready_rx.recv_timeout(Duration::from_secs(2)) {
        } else {
            let _send_result = stop_tx.send(());
            drop(handle.join());
            return Err(AegisError::ConfigError {
                message: "启动规则 watcher 失败".to_string(),
            });
        }

        self.watcher_thread = Some(handle);
        self.stop_tx = Some(stop_tx);
        Ok(())
    }
}

impl Drop for RuleManager {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _send_result = tx.send(());
        }
        if let Some(handle) = self.watcher_thread.take() {
            drop(handle.join());
        }
    }
}

fn build_rule_set(config_path: &Path, cfg: &AegisConfig) -> Result<RuleSet, AegisError> {
    let base_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let yara_rule_paths = resolve_paths(base_dir, cfg.security.yara_rule_paths.as_slice());
    let yara_rules = compile_yara_rules(yara_rule_paths.as_slice())?;

    Ok(RuleSet {
        timestomp_threshold_ms: cfg.security.timestomp_threshold_ms,
        scan_whitelist: cfg.security.scan_whitelist.clone(),
        yara_rule_paths,
        yara_rules,
    })
}

fn resolve_paths(base_dir: &Path, paths: &[String]) -> Vec<PathBuf> {
    paths
        .iter()
        .map(|p| {
            let pb = PathBuf::from(p);
            if pb.is_relative() {
                base_dir.join(pb)
            } else {
                pb
            }
        })
        .collect()
}

fn compile_yara_rules(paths: &[PathBuf]) -> Result<Option<Mutex<yara::Rules>>, AegisError> {
    if paths.is_empty() {
        return Ok(None);
    }

    let compiler = yara::Compiler::new().map_err(|e| AegisError::ConfigError {
        message: format!("YARA compiler init failed: {e}"),
    })?;

    let compiler = paths.iter().try_fold(compiler, |compiler, path| {
        let Some(path_str) = path.to_str() else {
            return Err(AegisError::ConfigError {
                message: format!("YARA 规则路径不是 UTF-8: {}", path.display()),
            });
        };
        compiler
            .add_rules_file(path_str)
            .map_err(|e| AegisError::ConfigError {
                message: format!("加载 YARA 规则失败（{}）: {e}", path.display()),
            })
    })?;

    let rules = compiler
        .compile_rules()
        .map_err(|e| AegisError::ConfigError {
            message: format!("编译 YARA 规则失败: {e}"),
        })?;
    Ok(Some(Mutex::new(rules)))
}

fn desired_watch_dirs(config_path: &Path, cfg: &AegisConfig) -> BTreeSet<PathBuf> {
    let base_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let mut out: BTreeSet<PathBuf> = BTreeSet::new();

    if let Some(dir) = config_path.parent() {
        if dir.as_os_str().is_empty() {
            out.insert(PathBuf::from("."));
        } else {
            out.insert(dir.to_path_buf());
        }
    } else {
        out.insert(PathBuf::from("."));
    }

    for path in resolve_paths(base_dir, cfg.security.yara_rule_paths.as_slice()) {
        if let Some(dir) = path.parent() {
            out.insert(dir.to_path_buf());
        }
    }
    out
}

fn is_relevant_rule_event(kind: EventKind) -> bool {
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
    use super::*;

    use std::time::{Duration, Instant};

    #[test]
    fn desired_watch_dirs_includes_dot_for_relative_config_path() {
        let cfg = AegisConfig::default();
        let dirs = desired_watch_dirs(Path::new("aegis.yml"), &cfg);
        assert!(dirs.contains(&PathBuf::from(".")));
    }

    #[test]
    fn rule_manager_loads_rules_and_scans() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("aegis.yml");
        let rules_path = dir.path().join("r.yar");

        std::fs::write(
            rules_path.as_path(),
            r#"
rule contains_abc {
  strings:
    $a = "abc"
  condition:
    $a
}
"#,
        )?;

        std::fs::write(
            config_path.as_path(),
            r#"
security:
  yara_rule_paths:
    - "r.yar"
"#,
        )?;

        let mgr = RuleManager::load(config_path.as_path())?;
        let rules = mgr.current();
        let matches = rules.scan_mem(b"zzabczz", 5)?;
        assert!(matches.iter().any(|id| id == "contains_abc"));
        Ok(())
    }

    #[test]
    fn rule_manager_hot_reload_replaces_rules() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("aegis.yml");
        let rules_path = dir.path().join("r.yar");

        std::fs::write(
            rules_path.as_path(),
            r#"
rule contains_abc {
  strings:
    $a = "abc"
  condition:
    $a
}
"#,
        )?;

        std::fs::write(
            config_path.as_path(),
            r#"
security:
  yara_rule_paths:
    - "r.yar"
"#,
        )?;

        let mut mgr = RuleManager::load(config_path.as_path())?;
        mgr.start_watching()?;

        {
            let rules = mgr.current();
            let matches = rules.scan_mem(b"zzabczz", 5)?;
            assert!(matches.iter().any(|id| id == "contains_abc"));
        }

        std::fs::write(
            rules_path.as_path(),
            r#"
rule contains_xyz {
  strings:
    $a = "xyz"
  condition:
    $a
}
"#,
        )?;

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let rules = mgr.current();
            let matches = rules.scan_mem(b"zzabczz", 5)?;
            if !matches.iter().any(|id| id == "contains_abc") {
                break;
            }
            if Instant::now() > deadline {
                return Err("rule manager did not reload in time".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Ok(())
    }

    #[test]
    fn rule_manager_keeps_last_good_rules_on_compile_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let config_path = dir.path().join("aegis.yml");
        let rules_path = dir.path().join("r.yar");

        std::fs::write(
            rules_path.as_path(),
            r#"
rule contains_abc {
  strings:
    $a = "abc"
  condition:
    $a
}
"#,
        )?;

        std::fs::write(
            config_path.as_path(),
            r#"
security:
  yara_rule_paths:
    - "r.yar"
"#,
        )?;

        let mut mgr = RuleManager::load(config_path.as_path())?;
        mgr.start_watching()?;

        {
            let rules = mgr.current();
            let matches = rules.scan_mem(b"zzabczz", 5)?;
            assert!(matches.iter().any(|id| id == "contains_abc"));
        }

        std::fs::write(rules_path.as_path(), "rule bad { condition: }")?;
        std::thread::sleep(Duration::from_millis(200));

        let rules = mgr.current();
        let matches = rules.scan_mem(b"zzabczz", 5)?;
        assert!(matches.iter().any(|id| id == "contains_abc"));
        Ok(())
    }
}
