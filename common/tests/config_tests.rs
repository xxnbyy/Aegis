#![allow(missing_docs)]

use std::path::PathBuf;
use std::time::Duration;

use common::config::{AegisConfig, ConfigManager};

#[test]
fn deserialize_yaml_sets_fields() -> Result<(), Box<dyn std::error::Error>> {
    let yaml = r#"
crypto:
  org_key_path: "./keys/org.der"
  user_passphrase: "test-passphrase"
governor:
  max_single_core_usage: 12
  net_packet_limit_per_sec: 6000
  io_limit_mb: 20
security:
  enable_native_plugins: false
  timestomp_threshold_ms: 2000
  scan_whitelist:
    - "C:/Windows/System32"
networking:
  c2_url: "https://c2.example.com"
  heartbeat_interval_sec: 30
"#;

    let cfg: AegisConfig = serde_yaml::from_str(yaml)?;
    cfg.validate()?;

    assert_eq!(
        cfg.crypto.org_key_path,
        Some(PathBuf::from("./keys/org.der"))
    );
    assert_eq!(
        cfg.crypto.user_passphrase.as_deref(),
        Some("test-passphrase")
    );
    assert_eq!(cfg.governor.max_single_core_usage, 12);
    assert_eq!(cfg.governor.net_packet_limit_per_sec, 6000);
    assert_eq!(cfg.governor.io_limit_mb, 20);
    assert!(!cfg.security.enable_native_plugins);
    assert_eq!(cfg.security.timestomp_threshold_ms, 2000);
    assert_eq!(cfg.security.scan_whitelist.len(), 1);
    assert_eq!(cfg.networking.c2_url, "https://c2.example.com");
    assert_eq!(cfg.networking.heartbeat_interval_sec, 30);
    Ok(())
}

#[test]
fn defaults_are_secure() {
    let cfg = AegisConfig::default();
    assert!(!cfg.security.enable_native_plugins);
    assert_eq!(cfg.security.timestomp_threshold_ms, 1000);
    assert_eq!(cfg.governor.max_single_core_usage, 5);
    assert_eq!(cfg.governor.net_packet_limit_per_sec, 5000);
    assert_eq!(cfg.governor.io_limit_mb, 10);
    assert_eq!(cfg.networking.heartbeat_interval_sec, 60);
}

#[test]
fn watcher_updates_config() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("aegis.yml");
    std::fs::write(path.as_path(), "networking:\n  c2_url: \"https://a\"\n")?;

    let mut mgr = ConfigManager::load(path.clone())?;
    mgr.start_watching()?;

    let first = mgr.current();
    assert_eq!(first.networking.c2_url, "https://a");

    std::fs::write(path.as_path(), "networking:\n  c2_url: \"https://b\"\n")?;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let current = mgr.current();
        if current.networking.c2_url == "https://b" {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err("config did not update in time".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
