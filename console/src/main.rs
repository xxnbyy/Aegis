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
use std::sync::{Arc, Mutex};
use tokio::signal;
use tokio::sync::broadcast;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

#[derive(Clone)]
struct AppState {
    console: Arc<Mutex<Console>>,
    expose_paths: bool,
    events: broadcast::Sender<WsEvent>,
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
    let (percent, message) = if status == console::TaskStatus::Pending {
        (100u32, "uploaded")
    } else if status == console::TaskStatus::Failed {
        (0u32, "failed")
    } else {
        (0u32, "uploading")
    };
    drop(st.events.send(WsEvent {
        channel: "analysis:progress".to_string(),
        payload: json!({
            "task_id": task_id,
            "percent": percent,
            "message": message,
            "status": status,
            "bytes_written": out.bytes_written,
            "next_sequence_id": out.next_sequence_id,
        }),
    }));
    if !st.expose_paths {
        out.case_path = None;
    }
}

fn send_ws(events: &broadcast::Sender<WsEvent>, channel: &str, payload: serde_json::Value) {
    drop(events.send(WsEvent {
        channel: channel.to_string(),
        payload,
    }));
}

async fn run_ai_job(st: AppState, task_id: String, decryption: Decryption) {
    let open_task_id = task_id.clone();
    let decryption_for_open = decryption.clone();
    let open = run_console(st.console.clone(), move |c| {
        c.open_artifact(OpenArtifactInput {
            source: Source::TaskId {
                task_id: open_task_id,
            },
            decryption: decryption_for_open,
            options: OpenArtifactOptions::default(),
        })
    })
    .await;

    let open_out = match open {
        Ok(v) => v,
        Err((_, e)) => {
            send_ws(
                &st.events,
                "ai:failed",
                json!({
                    "task_id": task_id.as_str(),
                    "percent": 0u32,
                    "message": e.0.message,
                    "code": e.0.code,
                }),
            );
            return;
        }
    };

    let case_id = open_out.case_id;
    send_ws(
        &st.events,
        "ai:progress",
        json!({
            "task_id": task_id.as_str(),
            "case_id": case_id.as_str(),
            "percent": 20u32,
            "message": "case opened",
        }),
    );

    send_ws(
        &st.events,
        "ai:progress",
        json!({
            "task_id": task_id.as_str(),
            "case_id": case_id.as_str(),
            "percent": 60u32,
            "message": "generating insight",
        }),
    );

    let case_id_for_call = case_id.clone();
    let insight = run_console(st.console.clone(), move |c| {
        c.get_ai_insight(GetAiInsightInput {
            case_id: case_id_for_call,
            node_id: None,
            context: None,
        })
    })
    .await;

    match insight {
        Ok(v) => {
            send_ws(
                &st.events,
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
            send_ws(
                &st.events,
                "ai:failed",
                json!({
                    "task_id": task_id.as_str(),
                    "case_id": case_id.as_str(),
                    "percent": 0u32,
                    "message": e.0.message,
                    "code": e.0.code,
                }),
            );
        }
    }
}

fn spawn_ai_job(st: AppState, task_id: &str) {
    let task_id_for_job = task_id.to_string();
    send_ws(
        &st.events,
        "ai:progress",
        json!({
            "task_id": task_id,
            "percent": 1u32,
            "message": "queued",
        }),
    );

    let Some(decryption) = resolve_ai_job_decryption() else {
        send_ws(
            &st.events,
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
    ws.on_upgrade(move |socket| async move {
        handle_ws(socket, &mut rx).await;
    })
}

async fn handle_ws(mut socket: WebSocket, rx: &mut broadcast::Receiver<WsEvent>) {
    loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    None | Some(Ok(WsMessage::Close(_)) | Err(_)) => break,
                    Some(Ok(_)) => {}
                }
            }
            ev = rx.recv() => {
                let Ok(ev) = ev else { continue; };
                let Ok(text) = serde_json::to_string(&ev) else { continue; };
                if socket.send(WsMessage::Text(text.into())).await.is_err() {
                    break;
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
    };

    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/ws", get(ws_events))
        .route("/api/v1/open_artifact", post(open_artifact))
        .route("/api/v1/get_graph_viewport", post(get_graph_viewport))
        .route("/api/v1/close_case/:case_id", post(close_case))
        .route("/api/v1/analyze_evidence", post(analyze_evidence))
        .route("/api/v1/analyze_evidence_bin", post(analyze_evidence_bin))
        .route("/api/v1/get_ai_insight", post(get_ai_insight))
        .route("/api/v1/get_task", post(get_task))
        .route("/api/v1/list_tasks", post(list_tasks))
        .with_state(st);

    if let Some(cors) = cors_layer(addr)? {
        app = app.layer(cors);
    }

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
