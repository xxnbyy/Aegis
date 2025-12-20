use tracing_subscriber::EnvFilter;

use crate::error::AegisError;

pub fn unix_timestamp_now() -> i64 {
    let dur = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d,
        Err(_) => std::time::Duration::from_secs(0),
    };
    i64::try_from(dur.as_secs()).unwrap_or(i64::MAX)
}

#[allow(clippy::missing_errors_doc)]
pub fn init_telemetry() -> Result<(), AegisError> {
    let filter = EnvFilter::try_from_env("AEGIS_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_writer(std::io::stdout)
        .try_init()
        .map_err(|e| AegisError::ConfigError {
            message: format!("初始化 telemetry 失败: {e}"),
        })
}

pub fn sample_memory_usage_mb() -> u32 {
    #[cfg(windows)]
    {
        sample_memory_usage_mb_windows()
    }
    #[cfg(not(windows))]
    {
        sample_memory_usage_mb_linux()
    }
}

#[cfg(windows)]
fn sample_memory_usage_mb_windows() -> u32 {
    use sysinfo::System;

    let mut sys = System::new();
    sys.refresh_memory();
    let used_memory_mb = sys.used_memory() / 1024;
    match u32::try_from(used_memory_mb) {
        Ok(v) => v,
        Err(_) => u32::MAX,
    }
}

#[cfg(not(windows))]
fn sample_memory_usage_mb_linux() -> u32 {
    let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    let Some((total_kb, available_kb)) = parse_proc_meminfo_kb(text.as_str()) else {
        return 0;
    };
    let used_memory_mb = total_kb.saturating_sub(available_kb) / 1024;
    match u32::try_from(used_memory_mb) {
        Ok(v) => v,
        Err(_) => u32::MAX,
    }
}

#[cfg(not(windows))]
fn parse_proc_meminfo_kb(text: &str) -> Option<(u64, u64)> {
    let mut total_kb: Option<u64> = None;
    let mut available_kb: Option<u64> = None;

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = parse_kb_value(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available_kb = parse_kb_value(rest);
        }
        if total_kb.is_some() && available_kb.is_some() {
            break;
        }
    }

    match (total_kb, available_kb) {
        (Some(t), Some(a)) => Some((t, a)),
        _ => None,
    }
}

#[cfg(not(windows))]
fn parse_kb_value(s: &str) -> Option<u64> {
    let number = s.split_whitespace().next()?;
    number.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    use super::parse_proc_meminfo_kb;

    #[cfg(not(windows))]
    #[test]
    fn meminfo_parser_extracts_total_and_available() {
        let sample = "MemTotal:       1024000 kB\nMemAvailable:    256000 kB\n";
        let (total, avail) = parse_proc_meminfo_kb(sample).unwrap_or((0, 0));
        assert_eq!(total, 1_024_000);
        assert_eq!(avail, 256_000);
    }
}
