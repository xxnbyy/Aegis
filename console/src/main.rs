#![allow(missing_docs)]

use axum::body::Bytes;
use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::error::{AegisError, ErrorCode};
use console::{
    AnalyzeEvidenceChunkInput, AnalyzeEvidenceMeta, AnalyzeEvidenceOutput, CloseCaseOutput,
    Console, ConsoleConfig, Decryption, GetAiInsightInput, GetAiInsightOutput,
    GetGraphViewportInput, GetGraphViewportOutput, GetTaskInput, GetTaskOutput, ListTasksInput,
    ListTasksOutput, OpenArtifactInput, OpenArtifactOptions, OpenArtifactOutput, PersistenceConfig,
    Source,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

struct ProbeCounters {
    emitted: AtomicU64,
    dropped: AtomicU64,
}

#[derive(Clone)]
struct AppState {
    console: Arc<Mutex<Console>>,
    expose_paths: bool,
    events: broadcast::Sender<WsEvent>,
    probe: Arc<ProbeCounters>,
}

#[derive(Clone, Serialize)]
struct WsEvent {
    channel: String,
    payload: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    message: String,
    code: Option<String>,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ErrorBody>)>;

fn build_app(addr: SocketAddr, st: AppState) -> Result<Router, Box<dyn std::error::Error>> {
    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/ws", get(ws_events))
        .route("/api/v1/open_artifact", post(open_artifact))
        .route("/api/v1/get_graph_viewport", post(get_graph_viewport))
        .route("/api/v1/close_case/{case_id}", post(close_case))
        .route("/api/v1/analyze_evidence", post(analyze_evidence))
        .route("/api/v1/analyze_evidence_bin", post(analyze_evidence_bin))
        .route("/api/v1/get_ai_insight", post(get_ai_insight))
        .route("/api/v1/get_task", post(get_task))
        .route("/api/v1/list_tasks", post(list_tasks))
        .with_state(st);

    if let Some(cors) = cors_layer(addr)? {
        app = app.layer(cors);
    }
    Ok(app)
}

async fn run_console<T, F>(
    console: Arc<Mutex<Console>>,
    f: F,
) -> Result<T, (StatusCode, Json<ErrorBody>)>
where
    T: Send + 'static,
    F: FnOnce(&mut Console) -> Result<T, AegisError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut c = console.lock().map_err(|_| AegisError::ProtocolError {
            message: "console lock poisoned".to_string(),
            code: Some(ErrorCode::Console733),
        })?;
        f(&mut c)
    })
    .await
    .map_err(|e| {
        map_err(AegisError::ProtocolError {
            message: format!("join error: {e}"),
            code: Some(ErrorCode::Console733),
        })
    })?
    .map_err(map_err)
}

fn post_analyze_evidence(st: &AppState, out: &mut AnalyzeEvidenceOutput) {
    let task_id = out.task_id.clone();
    let status = out.status.clone();
    let is_failed = status == console::TaskStatus::Failed;
    let (percent, message) = if status == console::TaskStatus::Pending {
        (100u32, "uploaded")
    } else if status == console::TaskStatus::Failed {
        (0u32, "failed")
    } else {
        (0u32, "uploading")
    };
    send_ws(
        st,
        "analysis:progress",
        json!({
            "task_id": task_id.clone(),
            "percent": percent,
            "message": message,
            "status": status,
            "bytes_written": out.bytes_written,
            "next_sequence_id": out.next_sequence_id,
        }),
    );
    if is_failed {
        let summary = format!("upload failed: {task_id}");
        emit_alert_new(st, "CRITICAL", summary.as_str());
    }
    if !st.expose_paths {
        out.case_path = None;
    }
}

fn send_ws(st: &AppState, channel: &str, payload: serde_json::Value) {
    st.probe.emitted.fetch_add(1, Ordering::Relaxed);
    let _send_result = st.events.send(WsEvent {
        channel: channel.to_string(),
        payload,
    });
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    let s = s.trim();
    if s.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= max_chars {
            out.push_str("...");
            break;
        }
        out.push(ch);
    }
    out
}

fn emit_alert_new(st: &AppState, severity: &str, summary: &str) {
    let summary = truncate_chars(summary, 160);
    if summary.is_empty() {
        return;
    }
    send_ws(
        st,
        "alert:new",
        json!({ "severity": severity, "summary": summary }),
    );
}

fn ai_insight_alert_severity(insight: &console::AiInsight) -> Option<&'static str> {
    let lvl = insight.risk_level.trim().to_ascii_uppercase();
    if lvl == "CRITICAL" {
        return Some("CRITICAL");
    }
    if insight.risk_score >= 90 {
        Some("CRITICAL")
    } else if insight.risk_score >= 80 {
        Some("HIGH")
    } else if insight.risk_score >= 60 || insight.is_risky {
        Some("WARNING")
    } else {
        None
    }
}

async fn try_mark_task_running(st: &AppState, task_id: &str) {
    let task_id_for_running = task_id.to_string();
    let _res = run_console(st.console.clone(), move |c| {
        c.mark_task_running(task_id_for_running.as_str())
    })
    .await;
}

async fn try_mark_task_done(st: &AppState, task_id: &str) {
    let task_id_for_done = task_id.to_string();
    let _res = run_console(st.console.clone(), move |c| {
        c.mark_task_done(task_id_for_done.as_str())
    })
    .await;
}

async fn try_mark_task_done_with_error(st: &AppState, task_id: &str, error_message: &str) {
    let task_id_for_done = task_id.to_string();
    let err_msg = error_message.to_string();
    let _res = run_console(st.console.clone(), move |c| {
        c.mark_task_done_with_error(task_id_for_done.as_str(), err_msg.as_str())
    })
    .await;
}

async fn open_case_for_task(
    st: &AppState,
    task_id: &str,
    decryption: Decryption,
) -> Result<OpenArtifactOutput, (StatusCode, Json<ErrorBody>)> {
    let open_task_id = task_id.to_string();
    run_console(st.console.clone(), move |c| {
        c.open_artifact(OpenArtifactInput {
            source: Source::TaskId {
                task_id: open_task_id,
            },
            decryption,
            options: OpenArtifactOptions::default(),
        })
    })
    .await
}

async fn generate_insight_for_case(
    st: &AppState,
    case_id: &str,
) -> Result<GetAiInsightOutput, (StatusCode, Json<ErrorBody>)> {
    let case_id_for_call = case_id.to_string();
    run_console(st.console.clone(), move |c| {
        c.get_ai_insight(GetAiInsightInput {
            case_id: case_id_for_call,
            node_id: None,
            context: None,
        })
    })
    .await
}

async fn run_ai_job(st: AppState, task_id: String, decryption: Decryption) {
    try_mark_task_running(&st, task_id.as_str()).await;

    let open_out = match open_case_for_task(&st, task_id.as_str(), decryption).await {
        Ok(v) => v,
        Err((_, e)) => {
            let ErrorBody { message, code } = e.0;
            try_mark_task_done_with_error(&st, task_id.as_str(), message.as_str()).await;
            emit_alert_new(&st, "CRITICAL", message.as_str());
            send_ws(
                &st,
                "ai:failed",
                json!({
                    "task_id": task_id.as_str(),
                    "percent": 0u32,
                    "message": message,
                    "code": code,
                }),
            );
            return;
        }
    };

    let case_id = open_out.case_id.clone();
    send_ws(
        &st,
        "ai:progress",
        json!({
            "task_id": task_id.as_str(),
            "case_id": case_id.as_str(),
            "percent": 20u32,
            "message": "case opened",
        }),
    );

    send_ws(
        &st,
        "ai:progress",
        json!({
            "task_id": task_id.as_str(),
            "case_id": case_id.as_str(),
            "percent": 60u32,
            "message": "generating insight",
        }),
    );

    let insight = generate_insight_for_case(&st, case_id.as_str()).await;

    match insight {
        Ok(v) => {
            try_mark_task_done(&st, task_id.as_str()).await;
            if let Some(sev) = ai_insight_alert_severity(&v.insight) {
                emit_alert_new(&st, sev, v.insight.summary.as_str());
            }
            send_ws(
                &st,
                "ai:done",
                json!({
                    "task_id": task_id.as_str(),
                    "case_id": v.case_id,
                    "percent": 100u32,
                    "message": "done",
                    "insight": v.insight,
                    "warnings": v.warnings,
                }),
            );
        }
        Err((_, e)) => {
            let ErrorBody { message, code } = e.0;
            try_mark_task_done_with_error(&st, task_id.as_str(), message.as_str()).await;
            emit_alert_new(&st, "CRITICAL", message.as_str());
            send_ws(
                &st,
                "ai:failed",
                json!({
                    "task_id": task_id.as_str(),
                    "case_id": case_id.as_str(),
                    "percent": 0u32,
                    "message": message,
                    "code": code,
                }),
            );
        }
    }
}

fn spawn_ai_job(st: AppState, task_id: &str) {
    let task_id_for_job = task_id.to_string();
    send_ws(
        &st,
        "ai:progress",
        json!({
            "task_id": task_id,
            "percent": 1u32,
            "message": "queued",
        }),
    );

    let Some(decryption) = resolve_ai_job_decryption() else {
        send_ws(
            &st,
            "ai:failed",
            json!({
                "task_id": task_id,
                "percent": 0u32,
                "message": "missing decryption for AI job",
                "code": ErrorCode::Console711.as_str(),
            }),
        );
        return;
    };

    tokio::spawn(run_ai_job(st, task_id_for_job, decryption));
}

fn spawn_probe_job(st: AppState) {
    spawn_probe_job_with_interval(st, Duration::from_secs(2));
}

fn spawn_probe_job_with_interval(st: AppState, interval: Duration) {
    let _probe_task = tokio::spawn(async move {
        let mut cpu = common::governor::CpuUsageTracker::new();
        let mut last_emitted = st.probe.emitted.load(Ordering::Relaxed);
        let mut last_dropped = st.probe.dropped.load(Ordering::Relaxed);

        loop {
            tokio::time::sleep(interval).await;

            let timestamp = common::telemetry::unix_timestamp_now();
            let cpu_usage_percent = cpu.get_max_single_core_usage();
            let memory_usage_mb = common::telemetry::sample_memory_usage_mb();

            let emitted = st.probe.emitted.load(Ordering::Relaxed);
            let dropped_events_count = st.probe.dropped.load(Ordering::Relaxed);

            let emitted_delta = emitted.saturating_sub(last_emitted);
            let dropped_delta = dropped_events_count.saturating_sub(last_dropped);
            let drop_rate_percent = if emitted_delta == 0 {
                0u32
            } else {
                let pct = (u128::from(dropped_delta) * 100u128) / u128::from(emitted_delta);
                u32::try_from(pct.min(100)).unwrap_or(100)
            };

            last_emitted = emitted;
            last_dropped = dropped_events_count;

            send_ws(
                &st,
                "probe:telemetry",
                json!({
                    "timestamp": timestamp,
                    "cpu_usage_percent": cpu_usage_percent,
                    "memory_usage_mb": memory_usage_mb,
                    "dropped_events_count": dropped_events_count,
                }),
            );

            let status = if drop_rate_percent >= 2 || cpu_usage_percent >= 95 {
                "Overloaded"
            } else {
                "Ok"
            };
            send_ws(
                &st,
                "probe:status",
                json!({
                    "status": status,
                    "dropped_events_count": dropped_events_count,
                    "drop_rate_percent": drop_rate_percent,
                }),
            );
        }
    });
}

fn map_err(e: AegisError) -> (StatusCode, Json<ErrorBody>) {
    match e {
        AegisError::ProtocolError { message, code } | AegisError::CryptoError { message, code } => {
            let status = match code {
                Some(ErrorCode::Console721 | ErrorCode::Console732) => StatusCode::NOT_FOUND,
                Some(
                    ErrorCode::Console701
                    | ErrorCode::Console702
                    | ErrorCode::Console703
                    | ErrorCode::Console711
                    | ErrorCode::Console722
                    | ErrorCode::Console731
                    | ErrorCode::Crypto003
                    | ErrorCode::Probe101
                    | ErrorCode::Probe201
                    | ErrorCode::Plugin501
                    | ErrorCode::Plugin502
                    | ErrorCode::Ai301
                    | ErrorCode::Ai302
                    | ErrorCode::Ai303
                    | ErrorCode::Ai399,
                ) => StatusCode::BAD_REQUEST,
                Some(ErrorCode::Console733) | None => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(ErrorBody {
                    message,
                    code: code.map(|c| c.as_str().to_string()),
                }),
            )
        }
        AegisError::ConfigError { message } => (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                message,
                code: None,
            }),
        ),
        AegisError::PacketTooLarge { size, limit } => (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorBody {
                message: format!("Packet size {size} exceeds limit {limit}"),
                code: None,
            }),
        ),
        AegisError::IoError(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorBody {
                message: err.to_string(),
                code: None,
            }),
        ),
    }
}

fn resolve_path(p: PathBuf) -> PathBuf {
    if p.is_absolute() {
        return p;
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(p)
}

fn read_env_trimmed(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn resolve_ai_job_decryption() -> Option<Decryption> {
    let pem = read_env_trimmed("AEGIS_CONSOLE_ORG_PRIVATE_KEY_PEM")
        .or_else(|| read_env_trimmed("AEGIS_ORG_PRIVATE_KEY_PEM"));
    if let Some(pem) = pem {
        return Some(Decryption::OrgPrivateKeyPem { pem });
    }

    let pem_path = read_env_trimmed("AEGIS_CONSOLE_ORG_PRIVATE_KEY_PATH")
        .or_else(|| read_env_trimmed("AEGIS_ORG_PRIVATE_KEY_PATH"));
    if let Some(path) = pem_path {
        let p = resolve_path(PathBuf::from(path));
        if let Ok(contents) = fs::read_to_string(p.as_path()) {
            let pem = contents.trim().to_string();
            if !pem.is_empty() {
                return Some(Decryption::OrgPrivateKeyPem { pem });
            }
        }
    }

    let passphrase = read_env_trimmed("AEGIS_CONSOLE_USER_PASSPHRASE")
        .or_else(|| read_env_trimmed("AEGIS_USER_PASSPHRASE"))
        .or_else(|| read_env_trimmed("AEGIS_DEV_PASSWORD"));
    passphrase.map(|passphrase| Decryption::UserPassphrase { passphrase })
}

fn cors_layer(addr: SocketAddr) -> Result<Option<CorsLayer>, Box<dyn std::error::Error>> {
    let allow_headers = [
        axum::http::header::CONTENT_TYPE,
        axum::http::header::HeaderName::from_static("x-aegis-ai-key"),
    ];
    if let Ok(v) = std::env::var("AEGIS_CONSOLE_CORS_ALLOW_ORIGIN") {
        let v = v.trim();
        let allow_origin = if v == "*" {
            AllowOrigin::any()
        } else {
            AllowOrigin::exact(HeaderValue::from_str(v)?)
        };
        let cors = CorsLayer::new()
            .allow_origin(allow_origin)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(allow_headers);
        return Ok(Some(cors));
    }

    if addr.ip().is_loopback() {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(allow_headers);
        return Ok(Some(cors));
    }

    Ok(None)
}

fn cfg_from_env() -> ConsoleConfig {
    let mut cfg = ConsoleConfig::default();

    if let Ok(v) = std::env::var("AEGIS_CONSOLE_MAX_LEVEL01_NODES")
        && let Ok(n) = v.parse::<usize>()
        && n > 0
    {
        cfg.max_level01_nodes = n;
    }

    if let Ok(v) = std::env::var("AEGIS_CONSOLE_DATA_DIR") {
        let data_dir = resolve_path(PathBuf::from(v));
        let db_path = data_dir.join("console.db");
        cfg.persistence = Some(PersistenceConfig { data_dir, db_path });
    }

    if let Ok(v) = std::env::var("AEGIS_CONSOLE_DB_PATH") {
        let db_path = resolve_path(PathBuf::from(v));
        let data_dir = db_path.parent().map_or_else(
            || std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            std::path::Path::to_path_buf,
        );
        cfg.persistence = Some(PersistenceConfig { data_dir, db_path });
    }

    cfg
}

async fn healthz() -> &'static str {
    "ok"
}

async fn open_artifact(
    State(st): State<AppState>,
    Json(input): Json<OpenArtifactInput>,
) -> ApiResult<OpenArtifactOutput> {
    let out = run_console(st.console.clone(), move |c| c.open_artifact(input)).await?;
    Ok(Json(out))
}

async fn get_graph_viewport(
    State(st): State<AppState>,
    Json(input): Json<GetGraphViewportInput>,
) -> ApiResult<GetGraphViewportOutput> {
    let out = run_console(st.console.clone(), move |c| c.get_graph_viewport(input)).await?;
    Ok(Json(out))
}

async fn close_case(
    State(st): State<AppState>,
    Path(case_id): Path<String>,
) -> ApiResult<CloseCaseOutput> {
    let out = run_console(st.console.clone(), move |c| c.close_case(case_id.as_str())).await?;
    Ok(Json(out))
}

async fn analyze_evidence(
    State(st): State<AppState>,
    Json(input): Json<AnalyzeEvidenceChunkInput>,
) -> ApiResult<AnalyzeEvidenceOutput> {
    let mut out = run_console(st.console.clone(), move |c| c.analyze_evidence(input)).await?;
    post_analyze_evidence(&st, &mut out);
    if out.status == console::TaskStatus::Pending {
        spawn_ai_job(st.clone(), out.task_id.as_str());
    }
    Ok(Json(out))
}

#[derive(Debug, Deserialize)]
struct AnalyzeEvidenceBinQuery {
    request_id: u64,
    sequence_id: u64,
    is_last: bool,
    filename: Option<String>,
    content_type: Option<String>,
}

async fn analyze_evidence_bin(
    State(st): State<AppState>,
    Query(q): Query<AnalyzeEvidenceBinQuery>,
    bytes: Bytes,
) -> ApiResult<AnalyzeEvidenceOutput> {
    let meta = if q.sequence_id == 0 {
        Some(AnalyzeEvidenceMeta {
            filename: q.filename,
            content_type: q.content_type,
        })
    } else {
        None
    };
    let input = AnalyzeEvidenceChunkInput {
        request_id: q.request_id,
        sequence_id: q.sequence_id,
        is_last: q.is_last,
        bytes: bytes.to_vec(),
        meta,
    };

    let mut out = run_console(st.console.clone(), move |c| c.analyze_evidence(input)).await?;
    post_analyze_evidence(&st, &mut out);
    if out.status == console::TaskStatus::Pending {
        spawn_ai_job(st.clone(), out.task_id.as_str());
    }
    Ok(Json(out))
}

async fn get_task(
    State(st): State<AppState>,
    Json(input): Json<GetTaskInput>,
) -> ApiResult<GetTaskOutput> {
    let mut out = run_console(st.console.clone(), move |c| c.get_task(input)).await?;

    if !st.expose_paths {
        out.case_path = None;
    }
    Ok(Json(out))
}

async fn list_tasks(
    State(st): State<AppState>,
    Json(input): Json<ListTasksInput>,
) -> ApiResult<ListTasksOutput> {
    let out = run_console(st.console.clone(), move |c| c.list_tasks(input)).await?;
    Ok(Json(out))
}

async fn get_ai_insight(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<GetAiInsightInput>,
) -> ApiResult<GetAiInsightOutput> {
    let ai_key = headers
        .get("x-aegis-ai-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let out = run_console(st.console.clone(), move |c| {
        c.get_ai_insight_with_ai_key(input, ai_key)
    })
    .await?;
    Ok(Json(out))
}

async fn ws_events(State(st): State<AppState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    let mut rx = st.events.subscribe();
    let probe = st.probe.clone();
    ws.on_upgrade(move |socket| async move {
        handle_ws(socket, &mut rx, probe).await;
    })
}

async fn handle_ws(
    mut socket: WebSocket,
    rx: &mut broadcast::Receiver<WsEvent>,
    probe: Arc<ProbeCounters>,
) {
    loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    None | Some(Ok(WsMessage::Close(_)) | Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            ev = rx.recv() => {
                match ev {
                    Ok(ev) => {
                        let Ok(text) = serde_json::to_string(&ev) else { continue; };
                        if socket.send(WsMessage::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        probe.dropped.fetch_add(n, Ordering::Relaxed);
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| {
        matches!(
            v.as_str(),
            "1" | "true" | "TRUE" | "True" | "yes" | "YES" | "on" | "ON"
        )
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("AEGIS_CONSOLE_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let addr: SocketAddr = bind.parse()?;

    let cfg = cfg_from_env();
    let c = Console::new(cfg);
    let (events, _events_rx) = broadcast::channel::<WsEvent>(1024);
    let st = AppState {
        console: Arc::new(Mutex::new(c)),
        expose_paths: env_flag("AEGIS_CONSOLE_EXPOSE_PATHS"),
        events,
        probe: Arc::new(ProbeCounters {
            emitted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }),
    };

    spawn_probe_job(st.clone());
    let app = build_app(addr, st)?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("aegis-console listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let shutdown = signal::ctrl_c().await;
            drop(shutdown);
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod http_e2e_tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    struct TestServer {
        base: String,
        shutdown: tokio::sync::oneshot::Sender<()>,
        _dir: tempfile::TempDir,
    }

    async fn spawn_test_server() -> Result<TestServer, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("data");
        let db_path = data_dir.join("console.db");
        std::fs::create_dir_all(data_dir.as_path())?;

        let cfg = ConsoleConfig {
            max_level01_nodes: 20_000,
            persistence: Some(PersistenceConfig { data_dir, db_path }),
        };
        let c = Console::new(cfg);
        let (events, _events_rx) = broadcast::channel::<WsEvent>(1024);
        let st = AppState {
            console: Arc::new(Mutex::new(c)),
            expose_paths: false,
            events,
            probe: Arc::new(ProbeCounters {
                emitted: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            }),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        spawn_probe_job_with_interval(st.clone(), Duration::from_millis(200));
        let app = build_app(addr, st)?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let _serve_result = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _shutdown_result = shutdown_rx.await;
                })
                .await;
        });

        Ok(TestServer {
            base: format!("http://{addr}"),
            shutdown: shutdown_tx,
            _dir: dir,
        })
    }

    #[tokio::test]
    async fn healthz_ok() -> Result<(), Box<dyn std::error::Error>> {
        let TestServer {
            base,
            shutdown,
            _dir,
        } = spawn_test_server().await?;
        let client = reqwest::Client::new();

        let resp = client
            .get(format!("{base}/healthz"))
            .timeout(Duration::from_secs(3))
            .send()
            .await?;
        assert!(resp.status().is_success());
        assert_eq!(resp.text().await?, "ok");

        let _send_result = shutdown.send(());
        Ok(())
    }

    #[tokio::test]
    async fn probe_emits_telemetry_and_status_events() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let data_dir = dir.path().join("data");
        let db_path = data_dir.join("console.db");
        std::fs::create_dir_all(data_dir.as_path())?;

        let cfg = ConsoleConfig {
            max_level01_nodes: 20_000,
            persistence: Some(PersistenceConfig { data_dir, db_path }),
        };
        let c = Console::new(cfg);
        let (events, _events_rx) = broadcast::channel::<WsEvent>(1024);
        let st = AppState {
            console: Arc::new(Mutex::new(c)),
            expose_paths: false,
            events,
            probe: Arc::new(ProbeCounters {
                emitted: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            }),
        };

        spawn_probe_job_with_interval(st.clone(), Duration::from_millis(50));
        let mut rx = st.events.subscribe();

        let ev1 = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await??;
        assert_eq!(ev1.channel, "probe:telemetry");
        assert!(ev1.payload.get("timestamp").is_some());
        assert!(ev1.payload.get("cpu_usage_percent").is_some());
        assert!(ev1.payload.get("memory_usage_mb").is_some());
        assert!(ev1.payload.get("dropped_events_count").is_some());

        let ev2 = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await??;
        assert_eq!(ev2.channel, "probe:status");
        assert!(ev2.payload.get("status").and_then(|v| v.as_str()).is_some());
        assert!(ev2.payload.get("dropped_events_count").is_some());
        assert!(ev2.payload.get("drop_rate_percent").is_some());

        Ok(())
    }

    #[tokio::test]
    async fn analyze_evidence_bin_then_get_task_and_list_tasks()
    -> Result<(), Box<dyn std::error::Error>> {
        let TestServer {
            base,
            shutdown,
            _dir,
        } = spawn_test_server().await?;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/api/v1/analyze_evidence_bin"))
            .query(&[
                ("request_id", "100"),
                ("sequence_id", "0"),
                ("is_last", "false"),
                ("filename", "t.aes"),
                ("content_type", "application/octet-stream"),
            ])
            .body(vec![1u8, 2, 3, 4])
            .timeout(Duration::from_secs(3))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await?;
        let task_id = v
            .get("task_id")
            .and_then(|x| x.as_str())
            .ok_or("missing task_id")?
            .to_string();
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("uploading"));
        assert!(v.get("case_path").is_some_and(serde_json::Value::is_null));
        assert_eq!(
            v.get("next_sequence_id")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );

        let resp = client
            .post(format!("{base}/api/v1/get_task"))
            .json(&json!({"task_id": task_id.clone()}))
            .timeout(Duration::from_secs(3))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await?;
        assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("uploading"));
        assert!(v.get("case_path").is_some_and(serde_json::Value::is_null));

        let resp = client
            .post(format!("{base}/api/v1/list_tasks"))
            .json(&json!({}))
            .timeout(Duration::from_secs(3))
            .send()
            .await?;
        assert!(resp.status().is_success());
        let v: serde_json::Value = resp.json().await?;
        let tasks = v
            .get("tasks")
            .and_then(|x| x.as_array())
            .ok_or("missing tasks")?;
        assert!(
            tasks
                .iter()
                .any(|x| x.get("task_id").and_then(|y| y.as_str()) == Some(task_id.as_str()))
        );

        let _send_result = shutdown.send(());
        Ok(())
    }

    #[tokio::test]
    async fn analyze_evidence_sequence0_without_meta_returns_console731()
    -> Result<(), Box<dyn std::error::Error>> {
        let TestServer {
            base,
            shutdown,
            _dir,
        } = spawn_test_server().await?;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/api/v1/analyze_evidence"))
            .json(&json!({
                "request_id": 101,
                "sequence_id": 0,
                "is_last": true,
                "bytes": [1,2,3],
                "meta": null
            }))
            .timeout(Duration::from_secs(3))
            .send()
            .await?;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v: serde_json::Value = resp.json().await?;
        assert_eq!(
            v.get("code").and_then(|x| x.as_str()),
            Some("AEGIS-CONSOLE-731")
        );

        let _send_result = shutdown.send(());
        Ok(())
    }
}
