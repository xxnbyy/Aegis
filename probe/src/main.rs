#![allow(missing_docs)]

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use common::config::{ConfigManager, load_yaml_file};
use common::governor::Governor;
use common::telemetry::init_telemetry;

mod embedded_key {
    include!(concat!(env!("OUT_DIR"), "/embedded_org_pubkey.rs"));
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
    let mut cfg = load_yaml_file(args.config_path.as_path())
        .map_err(|e| format!("加载配置失败（{}）: {e}", args.config_path.display()))?;
    if let Some(org_key_path) = args.org_key_path {
        cfg.crypto.org_key_path = Some(org_key_path);
    }
    cfg.validate().map_err(|e| format!("配置校验失败: {e}"))?;

    validate_key_requirements(
        is_unsigned_build(),
        embedded_key::EMBEDDED_ORG_PUBKEY_DER.is_some(),
        cfg.crypto.org_key_path.is_some(),
    )?;

    let mut mgr = ConfigManager::from_config(args.config_path, cfg)
        .map_err(|e| format!("初始化配置管理器失败: {e}"))?;
    mgr.start_watching()
        .map_err(|e| format!("启动配置热加载失败: {e}"))?;

    tracing::info!("probe started");
    let mut governor = Governor::new(mgr.current().governor.clone());
    loop {
        let cfg = mgr.current();
        governor.apply_config(cfg.governor.clone());
        let sleep = governor.tick();
        thread::sleep(Duration::from_millis(50).saturating_add(sleep));
    }
}

fn is_unsigned_build() -> bool {
    option_env!("AEGIS_IS_UNSIGNED_BUILD").is_some()
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
    config_path: PathBuf,
    org_key_path: Option<PathBuf>,
}

fn parse_args<I>(mut it: I) -> Result<ProbeArgs, String>
where
    I: Iterator<Item = String>,
{
    let mut config_path: Option<PathBuf> = None;
    let mut org_key_path: Option<PathBuf> = None;

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
            "--help" | "-h" => {
                return Err("Usage: probe --config <FILE> [--org-key-path <FILE>]\n".to_string());
            }
            other => return Err(format!("未知参数: {other}")),
        }
    }

    let Some(config_path) = config_path else {
        return Err("缺少必需参数: --config <FILE>".to_string());
    };

    Ok(ProbeArgs {
        config_path,
        org_key_path,
    })
}

#[cfg(test)]
mod tests {
    use super::validate_key_requirements;

    #[test]
    fn unsigned_build_requires_external_key_path() {
        assert!(validate_key_requirements(true, false, false).is_err());
        assert!(validate_key_requirements(true, true, false).is_err());
        assert!(validate_key_requirements(true, false, true).is_ok());
        assert!(validate_key_requirements(true, true, true).is_ok());
    }

    #[test]
    fn signed_build_requires_embedded_or_external_key() {
        assert!(validate_key_requirements(false, false, false).is_err());
        assert!(validate_key_requirements(false, true, false).is_ok());
        assert!(validate_key_requirements(false, false, true).is_ok());
        assert!(validate_key_requirements(false, true, true).is_ok());
    }
}
