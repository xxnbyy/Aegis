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
    Console, ConsoleConfig, GetGraphViewportInput, GetGraphViewportOutput, GetTaskInput,
    GetTaskOutput, ListTasksInput, ListTasksOutput, OpenArtifactInput, OpenArtifactOutput,
    PersistenceConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
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

fn cors_layer(addr: SocketAddr) -> Result<Option<CorsLayer>, Box<dyn std::error::Error>> {
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
            .allow_headers([axum::http::header::CONTENT_TYPE]);
        return Ok(Some(cors));
    }

    if addr.ip().is_loopback() {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE]);
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
    let console = st.console.clone();
    let out = tokio::task::spawn_blocking(move || {
        let mut c = console.lock().map_err(|_| AegisError::ProtocolError {
            message: "console lock poisoned".to_string(),
            code: Some(ErrorCode::Console733),
        })?;
        c.open_artifact(input)
    })
    .await
    .map_err(|e| {
        map_err(AegisError::ProtocolError {
            message: format!("join error: {e}"),
            code: Some(ErrorCode::Console733),
        })
    })?
    .map_err(map_err)?;
    Ok(Json(out))
}

async fn get_graph_viewport(
    State(st): State<AppState>,
    Json(input): Json<GetGraphViewportInput>,
) -> ApiResult<GetGraphViewportOutput> {
    let console = st.console.clone();
    let out = tokio::task::spawn_blocking(move || {
        let c = console.lock().map_err(|_| AegisError::ProtocolError {
            message: "console lock poisoned".to_string(),
            code: Some(ErrorCode::Console733),
        })?;
        c.get_graph_viewport(input)
    })
    .await
    .map_err(|e| {
        map_err(AegisError::ProtocolError {
            message: format!("join error: {e}"),
            code: Some(ErrorCode::Console733),
        })
    })?
    .map_err(map_err)?;
    Ok(Json(out))
}

async fn close_case(
    State(st): State<AppState>,
    Path(case_id): Path<String>,
) -> ApiResult<CloseCaseOutput> {
    let console = st.console.clone();
    let out = tokio::task::spawn_blocking(move || {
        let mut c = console.lock().map_err(|_| AegisError::ProtocolError {
            message: "console lock poisoned".to_string(),
            code: Some(ErrorCode::Console733),
        })?;
        c.close_case(case_id.as_str())
    })
    .await
    .map_err(|e| {
        map_err(AegisError::ProtocolError {
            message: format!("join error: {e}"),
            code: Some(ErrorCode::Console733),
        })
    })?
    .map_err(map_err)?;
    Ok(Json(out))
}

async fn analyze_evidence(
    State(st): State<AppState>,
    Json(input): Json<AnalyzeEvidenceChunkInput>,
) -> ApiResult<AnalyzeEvidenceOutput> {
    let console = st.console.clone();
    let mut out = tokio::task::spawn_blocking(move || {
        let mut c = console.lock().map_err(|_| AegisError::ProtocolError {
            message: "console lock poisoned".to_string(),
            code: Some(ErrorCode::Console733),
        })?;
        c.analyze_evidence(input)
    })
    .await
    .map_err(|e| {
        map_err(AegisError::ProtocolError {
            message: format!("join error: {e}"),
            code: Some(ErrorCode::Console733),
        })
    })?
    .map_err(map_err)?;

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

    let console = st.console.clone();
    let mut out = tokio::task::spawn_blocking(move || {
        let mut c = console.lock().map_err(|_| AegisError::ProtocolError {
            message: "console lock poisoned".to_string(),
            code: Some(ErrorCode::Console733),
        })?;
        c.analyze_evidence(input)
    })
    .await
    .map_err(|e| {
        map_err(AegisError::ProtocolError {
            message: format!("join error: {e}"),
            code: Some(ErrorCode::Console733),
        })
    })?
    .map_err(map_err)?;

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
    Ok(Json(out))
}

async fn get_task(
    State(st): State<AppState>,
    Json(input): Json<GetTaskInput>,
) -> ApiResult<GetTaskOutput> {
    let console = st.console.clone();
    let mut out = tokio::task::spawn_blocking(move || {
        let mut c = console.lock().map_err(|_| AegisError::ProtocolError {
            message: "console lock poisoned".to_string(),
            code: Some(ErrorCode::Console733),
        })?;
        c.get_task(input)
    })
    .await
    .map_err(|e| {
        map_err(AegisError::ProtocolError {
            message: format!("join error: {e}"),
            code: Some(ErrorCode::Console733),
        })
    })?
    .map_err(map_err)?;

    if !st.expose_paths {
        out.case_path = None;
    }
    Ok(Json(out))
}

async fn list_tasks(
    State(st): State<AppState>,
    Json(input): Json<ListTasksInput>,
) -> ApiResult<ListTasksOutput> {
    let console = st.console.clone();
    let out = tokio::task::spawn_blocking(move || {
        let mut c = console.lock().map_err(|_| AegisError::ProtocolError {
            message: "console lock poisoned".to_string(),
            code: Some(ErrorCode::Console733),
        })?;
        c.list_tasks(input)
    })
    .await
    .map_err(|e| {
        map_err(AegisError::ProtocolError {
            message: format!("join error: {e}"),
            code: Some(ErrorCode::Console733),
        })
    })?
    .map_err(map_err)?;
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
