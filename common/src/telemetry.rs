use tracing_subscriber::EnvFilter;

use crate::error::AegisError;

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
