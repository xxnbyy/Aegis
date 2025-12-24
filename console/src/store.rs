use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Seek, SeekFrom, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_kw::Kek;
use common::crypto;
use common::error::{AegisError, ErrorCode};
use common::protocol::{
    ArtifactBuilder, Command, MAX_ARTIFACT_CHUNK_SIZE, Message as ProtocolMessage, MessageHeader,
    MessagePayload, PayloadEnvelope, ProcessInfo, payload_envelope,
};
use prost::Message;
use rsa::Oaep;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use sha2::Sha256;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use tokio::runtime::Runtime;
use uuid::Uuid;

use crate::model::{
    AnalyzeEvidenceChunkInput, AnalyzeEvidenceOutput, CloseCaseOutput, Decryption, EdgeType,
    GetGraphViewportInput, GetGraphViewportOutput, GetTaskInput, GetTaskOutput, GraphEdge,
    GraphNode, ListTasksInput, ListTasksOutput, NodeType, OpenArtifactInput, OpenArtifactOutput,
    Source, TaskStatus, TaskSummary, ViewportLevel,
};

const USER_SLOT_LEN: usize = 40;
const MAX_LEVEL01_NODES: usize = 20_000;
const DEFAULT_LEVEL2_LIMIT: usize = 2000;

type ArtifactParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ConsoleConfig {
    pub max_level01_nodes: usize,
    pub persistence: Option<PersistenceConfig>,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        let data_dir = default_data_dir();
        let db_path = data_dir.join("console.db");
        Self {
            max_level01_nodes: MAX_LEVEL01_NODES,
            persistence: Some(PersistenceConfig { data_dir, db_path }),
        }
    }
}

pub struct Console {
    cfg: ConsoleConfig,
    cases: HashMap<String, CaseData>,
    persistence: Option<PersistenceState>,
    upload_sessions: HashMap<u64, UploadSession>,
}

struct UploadSession {
    task_id: String,
    case_path: PathBuf,
    builder: ArtifactBuilder<BufWriter<File>>,
}

struct PushChunkOutcome {
    task_id: String,
    case_path: PathBuf,
    bytes_written: u64,
    finished: bool,
    err: Option<AegisError>,
}

struct PersistenceState {
    cases_dir: PathBuf,
    pool: SqlitePool,
    rt: Runtime,
}

impl Console {
    pub fn new(cfg: ConsoleConfig) -> Self {
        Self {
            cfg,
            cases: HashMap::new(),
            persistence: None,
            upload_sessions: HashMap::new(),
        }
    }

    fn ensure_persistence(&mut self) -> Result<(), AegisError> {
        if self.persistence.is_none() {
            let Some(cfg) = self.cfg.persistence.clone() else {
                return Err(AegisError::ProtocolError {
                    message: "persistence 未启用".to_string(),
                    code: Some(ErrorCode::Console733),
                });
            };
            self.persistence = Some(PersistenceState::new(cfg)?);
        }
        Ok(())
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn open_artifact(
        &mut self,
        input: OpenArtifactInput,
    ) -> Result<OpenArtifactOutput, AegisError> {
        let bytes = match input.source {
            Source::LocalPath { path } => {
                std::fs::read(Path::new(path.as_str())).map_err(AegisError::IoError)?
            }
            Source::TaskId { task_id } => {
                self.ensure_persistence()?;
                let state = self
                    .persistence
                    .as_ref()
                    .ok_or_else(|| AegisError::ProtocolError {
                        message: "persistence 初始化失败".to_string(),
                        code: Some(ErrorCode::Console733),
                    })?;
                let case_path = state
                    .get_case_path_by_task_id(task_id.as_str())?
                    .ok_or_else(|| AegisError::ProtocolError {
                        message: "task_id 不存在".to_string(),
                        code: Some(ErrorCode::Console732),
                    })?;
                let safe_path = state.validate_case_path(case_path.as_str())?;
                std::fs::read(safe_path.as_path()).map_err(AegisError::IoError)?
            }
        };
        let header = parse_header(bytes.as_slice()).map_err(map_console_701)?;
        let case_id = Uuid::new_v4().to_string();
        let host_uuid_str = Uuid::from_bytes(header.host_uuid).to_string();
        let org_key_fp_hex = format!("{:016x}", header.org_key_fp);

        let mut warnings: Vec<String> = Vec::new();
        let mut sealed = false;
        let mut graph = Graph::default();
        let mut loaded = false;

        match input.decryption {
            Decryption::None => {
                warnings.push("WARN: decryption skipped (header only)".to_string());
            }
            other => {
                let rsa_ct_lens = [256usize, 384usize, 512usize];
                let attempt = decrypt_and_build_graph(
                    bytes.as_slice(),
                    &header,
                    other,
                    input.options.verify_hmac_if_present,
                    rsa_ct_lens.as_slice(),
                );
                match attempt {
                    Ok(r) => {
                        sealed = r.sealed;
                        warnings.extend(r.warnings);
                        graph = r.graph;
                        loaded = true;
                    }
                    Err(e) => return Err(map_open_artifact_err(e)),
                }
            }
        }

        self.cases.insert(
            case_id.clone(),
            CaseData {
                sealed,
                warnings: warnings.clone(),
                graph,
                loaded,
            },
        );

        Ok(OpenArtifactOutput {
            case_id,
            host_uuid: host_uuid_str,
            org_key_fp: org_key_fp_hex,
            sealed,
            warnings,
        })
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn get_graph_viewport(
        &self,
        input: GetGraphViewportInput,
    ) -> Result<GetGraphViewportOutput, AegisError> {
        let case =
            self.cases
                .get(input.case_id.as_str())
                .ok_or_else(|| AegisError::ProtocolError {
                    message: "case_id 不存在".to_string(),
                    code: Some(ErrorCode::Console721),
                })?;

        if !case.loaded {
            return Err(AegisError::ProtocolError {
                message: "case 未加载图谱（仅 header）".to_string(),
                code: Some(ErrorCode::Console711),
            });
        }

        match input.level {
            ViewportLevel::L2 => Ok(Self::viewport_level2(case, input.page)),
            ViewportLevel::L1 => {
                let Some(center_id) = input.center_node_id else {
                    return Err(AegisError::ProtocolError {
                        message: "level=1 缺少 center_node_id".to_string(),
                        code: Some(ErrorCode::Console722),
                    });
                };
                self.viewport_level1(case, center_id.as_str())
            }
            ViewportLevel::L0 => {
                let threshold = input.risk_score_threshold.unwrap_or(80);
                Ok(self.viewport_level0(case, threshold))
            }
        }
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn close_case(&mut self, case_id: &str) -> Result<CloseCaseOutput, AegisError> {
        let _ = self.cases.remove(case_id);
        Ok(CloseCaseOutput { ok: true })
    }

    fn validate_evidence_chunk_size(size: usize) -> Result<(), AegisError> {
        if size > MAX_ARTIFACT_CHUNK_SIZE {
            return Err(AegisError::ProtocolError {
                message: format!("chunk bytes 超限: {size} > {MAX_ARTIFACT_CHUNK_SIZE}"),
                code: Some(ErrorCode::Console731),
            });
        }
        Ok(())
    }

    fn ensure_upload_session_ready(
        upload_sessions: &mut HashMap<u64, UploadSession>,
        state: &PersistenceState,
        input: &AnalyzeEvidenceChunkInput,
        now_ms: i64,
    ) -> Result<(), AegisError> {
        let request_id = input.request_id;
        if upload_sessions.contains_key(&request_id) {
            return Ok(());
        }

        if input.sequence_id == 0 {
            if state.request_id_exists(request_id)? {
                return Err(AegisError::ProtocolError {
                    message: "request_id 已存在，请从 next_sequence_id 续传或更换 request_id"
                        .to_string(),
                    code: Some(ErrorCode::Console731),
                });
            }
            if input.meta.is_none() {
                return Err(AegisError::ProtocolError {
                    message: "sequence_id=0 必须携带 meta".to_string(),
                    code: Some(ErrorCode::Console731),
                });
            }
            Self::start_new_upload_session(upload_sessions, state, request_id, now_ms)?;
            return Ok(());
        }

        Self::try_rehydrate_upload_session(
            upload_sessions,
            state,
            request_id,
            input.sequence_id,
            now_ms,
        )
    }

    fn start_new_upload_session(
        upload_sessions: &mut HashMap<u64, UploadSession>,
        state: &PersistenceState,
        request_id: u64,
        now_ms: i64,
    ) -> Result<(), AegisError> {
        let task_id = Uuid::new_v4().to_string();
        let case_path = state.cases_dir.join(format!("{task_id}.aes"));
        let case_path_str = case_path.display().to_string();

        let file = File::create(case_path.as_path())
            .map_err(|e| map_console_733(AegisError::IoError(e), "创建落盘文件失败"))?;
        let writer = BufWriter::new(file);
        let builder = ArtifactBuilder::new(request_id, writer);

        state.insert_task_row(
            task_id.as_str(),
            request_id,
            &TaskStatus::Uploading,
            now_ms,
            now_ms,
            case_path_str.as_str(),
        )?;

        upload_sessions.insert(
            request_id,
            UploadSession {
                task_id,
                case_path,
                builder,
            },
        );

        Ok(())
    }

    fn try_rehydrate_upload_session(
        upload_sessions: &mut HashMap<u64, UploadSession>,
        state: &PersistenceState,
        request_id: u64,
        sequence_id: u64,
        now_ms: i64,
    ) -> Result<(), AegisError> {
        let Some(task) = state.get_task_row_by_request_id(request_id)? else {
            return Err(AegisError::ProtocolError {
                message: "upload session 不存在".to_string(),
                code: Some(ErrorCode::Console731),
            });
        };

        if task.status != TaskStatus::Failed {
            return Err(AegisError::ProtocolError {
                message: "upload session 不存在".to_string(),
                code: Some(ErrorCode::Console731),
            });
        }

        if task.error_message.as_deref() != Some("console restarted during upload") {
            return Err(AegisError::ProtocolError {
                message: "failed task 不支持续传".to_string(),
                code: Some(ErrorCode::Console731),
            });
        }

        if task.next_sequence_id != Some(sequence_id) {
            return Err(AegisError::ProtocolError {
                message: "续传 sequence_id 不匹配".to_string(),
                code: Some(ErrorCode::Console731),
            });
        }

        let next_sequence_id = task.next_sequence_id.unwrap_or(0);
        let stored_bytes_written = task.bytes_written.unwrap_or(0);

        let Some(case_path_str) = task.case_path else {
            return Err(AegisError::ProtocolError {
                message: "task 缺少 case_path".to_string(),
                code: Some(ErrorCode::Console733),
            });
        };
        let case_path = state.validate_case_path(case_path_str.as_str())?;
        if !case_path.exists() {
            return Err(AegisError::ProtocolError {
                message: "续传文件不存在".to_string(),
                code: Some(ErrorCode::Console731),
            });
        }
        let file_len = case_path
            .metadata()
            .map_err(|e| map_console_733(AegisError::IoError(e), "读取续传文件元信息失败"))?
            .len();
        let bytes_written = u64::min(stored_bytes_written, file_len);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(case_path.as_path())
            .map_err(|e| map_console_733(AegisError::IoError(e), "打开续传文件失败"))?;
        file.set_len(bytes_written)
            .map_err(|e| map_console_733(AegisError::IoError(e), "截断续传文件失败"))?;
        file.seek(SeekFrom::End(0))
            .map_err(|e| map_console_733(AegisError::IoError(e), "定位续传文件失败"))?;
        let writer = BufWriter::new(file);
        let builder =
            ArtifactBuilder::new_with_state(request_id, writer, next_sequence_id, bytes_written);

        state.mark_task_uploading(
            task.task_id.as_str(),
            now_ms,
            bytes_written,
            next_sequence_id,
        )?;

        upload_sessions.insert(
            request_id,
            UploadSession {
                task_id: task.task_id,
                case_path,
                builder,
            },
        );
        Ok(())
    }

    fn push_upload_chunk(
        upload_sessions: &mut HashMap<u64, UploadSession>,
        request_id: u64,
        sequence_id: u64,
        is_last: bool,
        bytes: Vec<u8>,
    ) -> Result<PushChunkOutcome, AegisError> {
        let message = ProtocolMessage {
            header: MessageHeader {
                request_id,
                timestamp: 0,
                command: Command::UploadArtifactChunk,
            },
            payload: MessagePayload::ArtifactChunk(common::protocol::ArtifactChunk {
                sequence_id,
                is_last,
                bytes,
            }),
        };

        let session =
            upload_sessions
                .get_mut(&request_id)
                .ok_or_else(|| AegisError::ProtocolError {
                    message: "upload session 不存在".to_string(),
                    code: Some(ErrorCode::Console731),
                })?;

        let task_id = session.task_id.clone();
        let case_path = session.case_path.clone();

        let res = session.builder.push(&message);
        let bytes_written = session.builder.bytes_written();
        let finished = session.builder.is_finished();

        Ok(PushChunkOutcome {
            task_id,
            case_path,
            bytes_written,
            finished,
            err: res.err(),
        })
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn analyze_evidence(
        &mut self,
        input: AnalyzeEvidenceChunkInput,
    ) -> Result<AnalyzeEvidenceOutput, AegisError> {
        Self::validate_evidence_chunk_size(input.bytes.len())?;
        self.ensure_persistence()?;
        let state = self
            .persistence
            .as_ref()
            .ok_or_else(|| AegisError::ProtocolError {
                message: "persistence 初始化失败".to_string(),
                code: Some(ErrorCode::Console733),
            })?;
        let now_ms = unix_timestamp_now_ms();
        let request_id = input.request_id;

        Self::ensure_upload_session_ready(&mut self.upload_sessions, state, &input, now_ms)?;

        let outcome = Self::push_upload_chunk(
            &mut self.upload_sessions,
            request_id,
            input.sequence_id,
            input.is_last,
            input.bytes,
        )?;

        if let Some(e) = outcome.err {
            let _ = self.upload_sessions.remove(&request_id);
            state.mark_task_failed(outcome.task_id.as_str(), now_ms, e.to_string().as_str())?;
            let _remove_err = fs::remove_file(outcome.case_path.as_path());
            return Err(map_console_731(e));
        }

        let mut status = TaskStatus::Uploading;
        let next_sequence_id = input.sequence_id.saturating_add(1);
        state.update_task_progress(
            outcome.task_id.as_str(),
            &status,
            now_ms,
            outcome.bytes_written,
            next_sequence_id,
        )?;

        if outcome.finished {
            status = TaskStatus::Pending;
            if let Some(session) = self.upload_sessions.remove(&request_id) {
                let mut writer = session.builder.into_inner();
                let _flush_err = writer.flush();
            }
            state.update_task_progress(
                outcome.task_id.as_str(),
                &status,
                now_ms,
                outcome.bytes_written,
                next_sequence_id,
            )?;
        }

        Ok(AnalyzeEvidenceOutput {
            task_id: outcome.task_id,
            status,
            bytes_written: Some(outcome.bytes_written),
            next_sequence_id: Some(next_sequence_id),
            case_path: Some(outcome.case_path.display().to_string()),
        })
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn get_task(&mut self, input: GetTaskInput) -> Result<GetTaskOutput, AegisError> {
        self.ensure_persistence()?;
        let state = self
            .persistence
            .as_ref()
            .ok_or_else(|| AegisError::ProtocolError {
                message: "persistence 初始化失败".to_string(),
                code: Some(ErrorCode::Console733),
            })?;
        let task_id = input.task_id;
        let task =
            state
                .get_task_row(task_id.as_str())?
                .ok_or_else(|| AegisError::ProtocolError {
                    message: "task_id 不存在".to_string(),
                    code: Some(ErrorCode::Console732),
                })?;
        Ok(task)
    }

    #[allow(clippy::missing_errors_doc)]
    pub fn list_tasks(&mut self, input: ListTasksInput) -> Result<ListTasksOutput, AegisError> {
        self.ensure_persistence()?;
        let state = self
            .persistence
            .as_ref()
            .ok_or_else(|| AegisError::ProtocolError {
                message: "persistence 初始化失败".to_string(),
                code: Some(ErrorCode::Console733),
            })?;
        state.list_tasks(input.page)
    }

    fn viewport_level2(
        case: &CaseData,
        page: Option<crate::model::Page>,
    ) -> GetGraphViewportOutput {
        let cursor = page
            .as_ref()
            .and_then(|p| p.cursor.clone())
            .unwrap_or_else(|| "0".to_string());
        let start: usize = cursor.parse().unwrap_or(0);
        let limit = page
            .and_then(|p| p.limit)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(DEFAULT_LEVEL2_LIMIT);

        let nodes: Vec<GraphNode> = case
            .graph
            .nodes
            .values()
            .skip(start)
            .take(limit)
            .cloned()
            .collect();

        let node_ids: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
        let edges: Vec<GraphEdge> = case
            .graph
            .edges
            .iter()
            .filter(|e| node_ids.contains(e.src.as_str()) && node_ids.contains(e.dst.as_str()))
            .cloned()
            .collect();

        let end = start.saturating_add(nodes.len());
        let next_cursor = if end < case.graph.nodes.len() {
            Some(end.to_string())
        } else {
            None
        };

        let mut warnings: Vec<String> = Vec::new();
        if !case.sealed {
            warnings.push("WARN: case not sealed".to_string());
        }
        warnings.extend(case.warnings.iter().cloned());

        GetGraphViewportOutput {
            nodes,
            edges,
            next_cursor,
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
        }
    }

    fn viewport_level1(
        &self,
        case: &CaseData,
        center_id: &str,
    ) -> Result<GetGraphViewportOutput, AegisError> {
        let Some(center) = case.graph.nodes.get(center_id) else {
            return Err(AegisError::ProtocolError {
                message: "center_node_id 不存在".to_string(),
                code: Some(ErrorCode::Console721),
            });
        };

        let mut nodes: HashMap<String, GraphNode> = HashMap::new();
        nodes.insert(center.id.clone(), center.clone());

        let mut edge_out: Vec<GraphEdge> = Vec::new();
        for e in &case.graph.edges {
            if e.src == center_id || e.dst == center_id {
                edge_out.push(e.clone());
                if let Some(n) = case.graph.nodes.get(e.src.as_str()) {
                    nodes.entry(n.id.clone()).or_insert_with(|| n.clone());
                }
                if let Some(n) = case.graph.nodes.get(e.dst.as_str()) {
                    nodes.entry(n.id.clone()).or_insert_with(|| n.clone());
                }
            }
        }

        let mut warnings: Vec<String> = Vec::new();
        if !case.sealed {
            warnings.push("WARN: case not sealed".to_string());
        }
        warnings.extend(case.warnings.iter().cloned());

        if nodes.len() > self.cfg.max_level01_nodes {
            warnings.push("WARN: level1 result exceeded hard limit; downsampled".to_string());
            let mut items: Vec<GraphNode> = nodes.into_values().collect();
            items.sort_by_key(|n| std::cmp::Reverse(n.risk_score));
            let mut keep: HashMap<String, GraphNode> = HashMap::new();
            keep.insert(center.id.clone(), center.clone());
            for n in items {
                if keep.len() >= self.cfg.max_level01_nodes {
                    break;
                }
                keep.entry(n.id.clone()).or_insert(n);
            }
            let keep_ids: HashSet<String> = keep.keys().cloned().collect();
            edge_out
                .retain(|e| keep_ids.contains(e.src.as_str()) && keep_ids.contains(e.dst.as_str()));
            nodes = keep;
        }

        Ok(GetGraphViewportOutput {
            nodes: nodes.into_values().collect(),
            edges: edge_out,
            next_cursor: None,
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
        })
    }

    fn build_undirected_adj(edges: &[GraphEdge]) -> HashMap<String, Vec<String>> {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for e in edges {
            adj.entry(e.src.clone()).or_default().push(e.dst.clone());
            adj.entry(e.dst.clone()).or_default().push(e.src.clone());
        }
        adj
    }

    fn connect_high_nodes(
        case: &CaseData,
        high: &[&GraphNode],
        adj: &HashMap<String, Vec<String>>,
    ) -> (HashMap<String, GraphNode>, usize, bool) {
        let mut selected: HashMap<String, GraphNode> = HashMap::new();
        let mut connected_high: HashSet<String> = HashSet::new();

        let Some(root) = high.first() else {
            return (selected, 0, false);
        };
        let root_id = root.id.clone();

        if let Some(n) = case.graph.nodes.get(root_id.as_str()) {
            selected.insert(n.id.clone(), n.clone());
        } else {
            selected.insert(root_id.clone(), (*root).clone());
        }
        connected_high.insert(root_id);

        let high_ids: HashSet<String> = high.iter().map(|n| n.id.clone()).collect();

        let mut disconnected = false;
        while connected_high.len() < high_ids.len() {
            let mut q: VecDeque<String> = VecDeque::new();
            let mut parent: HashMap<String, Option<String>> = HashMap::new();
            for s in selected.keys() {
                q.push_back(s.clone());
                parent.insert(s.clone(), None);
            }

            let mut found: Option<String> = None;
            while let Some(cur) = q.pop_front() {
                if high_ids.contains(cur.as_str()) && !connected_high.contains(cur.as_str()) {
                    found = Some(cur);
                    break;
                }
                if let Some(neighbors) = adj.get(cur.as_str()) {
                    for n in neighbors {
                        if parent.contains_key(n.as_str()) {
                            continue;
                        }
                        parent.insert(n.clone(), Some(cur.clone()));
                        q.push_back(n.clone());
                    }
                }
            }

            let Some(target) = found else {
                disconnected = true;
                break;
            };

            let mut path: Vec<String> = Vec::new();
            let mut cur = Some(target.clone());
            while let Some(id) = cur {
                path.push(id.clone());
                cur = parent.get(id.as_str()).and_then(std::clone::Clone::clone);
            }

            for id in path {
                if let Some(node) = case.graph.nodes.get(id.as_str()) {
                    selected
                        .entry(node.id.clone())
                        .or_insert_with(|| node.clone());
                }
            }
            connected_high.insert(target);
        }

        let unreachable = high_ids.len().saturating_sub(connected_high.len());
        (selected, unreachable, disconnected)
    }

    fn select_level0_subgraph(
        &self,
        case: &CaseData,
        high: &[&GraphNode],
        adj: &HashMap<String, Vec<String>>,
    ) -> (HashMap<String, GraphNode>, usize, bool, bool) {
        let mut high_limit = high.len();
        let mut selected: HashMap<String, GraphNode> = HashMap::new();
        let mut unreachable_high = 0usize;
        let mut disconnected = false;
        let mut downsampled = false;

        while high_limit > 0 {
            let (s, unreachable, disc) = Self::connect_high_nodes(case, &high[..high_limit], adj);
            if s.len() <= self.cfg.max_level01_nodes || high_limit == 1 {
                selected = s;
                unreachable_high = unreachable;
                disconnected = disc;
                downsampled = high_limit < high.len();
                break;
            }
            high_limit = std::cmp::max(1, high_limit.saturating_mul(3) / 4);
        }

        (selected, unreachable_high, disconnected, downsampled)
    }

    fn viewport_level0(&self, case: &CaseData, threshold: u32) -> GetGraphViewportOutput {
        let mut high: Vec<&GraphNode> = case
            .graph
            .nodes
            .values()
            .filter(|n| n.risk_score >= threshold)
            .collect();
        high.sort_by_key(|n| std::cmp::Reverse(n.risk_score));

        let mut warnings: Vec<String> = Vec::new();
        if !case.sealed {
            warnings.push("WARN: case not sealed".to_string());
        }
        warnings.extend(case.warnings.iter().cloned());
        if high.is_empty() {
            warnings.push("WARN: no nodes above threshold".to_string());
            return GetGraphViewportOutput {
                nodes: Vec::new(),
                edges: Vec::new(),
                next_cursor: None,
                warnings: Some(warnings),
            };
        }

        let adj = Self::build_undirected_adj(case.graph.edges.as_slice());
        let (mut selected, unreachable_high, disconnected, downsampled) =
            self.select_level0_subgraph(case, high.as_slice(), &adj);

        if downsampled {
            warnings.push("WARN: level0 result exceeded hard limit; downsampled".to_string());
        }
        if disconnected {
            warnings.push("WARN: graph is disconnected".to_string());
        }
        if unreachable_high > 0 {
            warnings.push(format!(
                "WARN: {unreachable_high} high-risk nodes unreachable from selected subgraph"
            ));
        }

        if selected.len() == 1 {
            let root = high[0].id.as_str();
            for n in adj.get(root).map_or(&[] as &[String], Vec::as_slice) {
                if selected.len() >= self.cfg.max_level01_nodes {
                    break;
                }
                if let Some(node) = case.graph.nodes.get(n.as_str()) {
                    selected
                        .entry(node.id.clone())
                        .or_insert_with(|| node.clone());
                }
            }
        }

        let mut edge_out: Vec<GraphEdge> = Vec::new();
        for e in &case.graph.edges {
            if selected.contains_key(e.src.as_str()) && selected.contains_key(e.dst.as_str()) {
                edge_out.push(e.clone());
            }
        }

        GetGraphViewportOutput {
            nodes: selected.into_values().collect(),
            edges: edge_out,
            next_cursor: None,
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AesHeader {
    kdf_salt: [u8; crypto::AES_KDF_SALT_LEN],
    host_uuid: [u8; crypto::AES_HOST_UUID_LEN],
    org_key_fp: u64,
}

fn parse_header(bytes: &[u8]) -> Result<AesHeader, AegisError> {
    let header = bytes
        .get(..crypto::AES_HEADER_LEN)
        .ok_or(AegisError::ProtocolError {
            message: "文件长度不足（Header）".to_string(),
            code: Some(ErrorCode::Console701),
        })?;
    if header.get(0..crypto::AES_MAGIC.len()) != Some(crypto::AES_MAGIC.as_slice()) {
        return Err(AegisError::ProtocolError {
            message: "Magic 不匹配".to_string(),
            code: Some(ErrorCode::Console701),
        });
    }
    let version = *header.get(0x05).ok_or(AegisError::ProtocolError {
        message: "Header version 越界".to_string(),
        code: Some(ErrorCode::Console701),
    })?;
    if version != crypto::AES_VERSION_V1 {
        return Err(AegisError::ProtocolError {
            message: format!("不支持的 Version: {version}"),
            code: Some(ErrorCode::Console701),
        });
    }
    let cipher = *header.get(0x06).ok_or(AegisError::ProtocolError {
        message: "Header cipher 越界".to_string(),
        code: Some(ErrorCode::Console701),
    })?;
    if cipher != crypto::AES_CIPHER_ID_XCHACHA20_POLY1305 {
        return Err(AegisError::ProtocolError {
            message: format!("不支持的 CipherID: {cipher}"),
            code: Some(ErrorCode::Console701),
        });
    }
    let comp = *header.get(0x07).ok_or(AegisError::ProtocolError {
        message: "Header comp 越界".to_string(),
        code: Some(ErrorCode::Console701),
    })?;
    if comp != crypto::AES_COMP_ID_NONE {
        return Err(AegisError::ProtocolError {
            message: format!("不支持的 CompID: {comp}"),
            code: Some(ErrorCode::Console701),
        });
    }

    let kdf_salt: [u8; crypto::AES_KDF_SALT_LEN] = header
        .get(crypto::AES_KDF_SALT_OFFSET..crypto::AES_KDF_SALT_OFFSET + crypto::AES_KDF_SALT_LEN)
        .ok_or(AegisError::ProtocolError {
            message: "读取 KDF_Salt 失败".to_string(),
            code: Some(ErrorCode::Console701),
        })?
        .try_into()
        .map_err(|_| AegisError::ProtocolError {
            message: "读取 KDF_Salt 失败".to_string(),
            code: Some(ErrorCode::Console701),
        })?;
    let host_uuid: [u8; crypto::AES_HOST_UUID_LEN] = header
        .get(crypto::AES_HOST_UUID_OFFSET..crypto::AES_HOST_UUID_OFFSET + crypto::AES_HOST_UUID_LEN)
        .ok_or(AegisError::ProtocolError {
            message: "读取 HostUUID 失败".to_string(),
            code: Some(ErrorCode::Console701),
        })?
        .try_into()
        .map_err(|_| AegisError::ProtocolError {
            message: "读取 HostUUID 失败".to_string(),
            code: Some(ErrorCode::Console701),
        })?;
    let org_fp_bytes: [u8; 8] = header
        .get(crypto::AES_ORG_KEY_FP_OFFSET..crypto::AES_ORG_KEY_FP_OFFSET + 8)
        .ok_or(AegisError::ProtocolError {
            message: "读取 OrgKeyFP 失败".to_string(),
            code: Some(ErrorCode::Console701),
        })?
        .try_into()
        .map_err(|_| AegisError::ProtocolError {
            message: "读取 OrgKeyFP 失败".to_string(),
            code: Some(ErrorCode::Console701),
        })?;
    let org_key_fp = u64::from_be_bytes(org_fp_bytes);

    Ok(AesHeader {
        kdf_salt,
        host_uuid,
        org_key_fp,
    })
}

fn map_console_701(e: AegisError) -> AegisError {
    match e {
        AegisError::ProtocolError { message, .. } => AegisError::ProtocolError {
            message,
            code: Some(ErrorCode::Console701),
        },
        other => other,
    }
}

fn map_open_artifact_err(e: AegisError) -> AegisError {
    match e {
        AegisError::PacketTooLarge { size, limit } => AegisError::ProtocolError {
            message: format!("PayloadLen 超限: {size} > {limit}"),
            code: Some(ErrorCode::Console703),
        },
        AegisError::CryptoError {
            message,
            code: Some(ErrorCode::Crypto003),
        } => {
            if message.contains("PayloadLen") {
                AegisError::ProtocolError {
                    message,
                    code: Some(ErrorCode::Console703),
                }
            } else {
                AegisError::CryptoError {
                    message,
                    code: Some(ErrorCode::Crypto003),
                }
            }
        }
        AegisError::CryptoError { message, .. } => AegisError::CryptoError {
            message,
            code: Some(ErrorCode::Console702),
        },
        AegisError::ProtocolError { message, code } => AegisError::ProtocolError {
            message,
            code: code.or(Some(ErrorCode::Console701)),
        },
        other => other,
    }
}

fn decrypt_and_build_graph(
    bytes: &[u8],
    header: &AesHeader,
    decryption: Decryption,
    verify_hmac_if_present: bool,
    rsa_ct_lens: &[usize],
) -> Result<DecryptBuildResult, AegisError> {
    let mut warnings: Vec<String> = Vec::new();
    match decryption {
        Decryption::OrgPrivateKeyPem { pem } => {
            let private_key = parse_rsa_private_key(pem.as_str()).map_err(map_open_artifact_err)?;
            let rsa_ct_len = private_key.size();
            let (user_slot, rsa_ct, stream) = read_artifact_parts(bytes, rsa_ct_len)?;
            let _ = user_slot;
            let session_key_bytes =
                private_key
                    .decrypt(Oaep::new::<Sha256>(), rsa_ct)
                    .map_err(|e| AegisError::CryptoError {
                        message: format!("RSA-OAEP 解密 SessionKey 失败: {e}"),
                        code: Some(ErrorCode::Console702),
                    })?;
            let session_key: [u8; 32] =
                session_key_bytes
                    .try_into()
                    .map_err(|_| AegisError::CryptoError {
                        message: "SessionKey 长度不是 32 bytes".to_string(),
                        code: Some(ErrorCode::Console702),
                    })?;
            let (sealed, stream_data) = verify_and_trim_stream(
                bytes,
                stream,
                &session_key,
                verify_hmac_if_present,
                &mut warnings,
            )?;
            let graph = build_graph_from_stream(header, stream_data, &session_key, &mut warnings)?;
            Ok(DecryptBuildResult {
                sealed,
                warnings,
                graph,
            })
        }
        Decryption::UserPassphrase { passphrase } => {
            let mut last_err: Option<AegisError> = None;
            for rsa_ct_len in rsa_ct_lens {
                let attempt = decrypt_with_passphrase_and_len(
                    bytes,
                    header,
                    passphrase.as_str(),
                    *rsa_ct_len,
                    verify_hmac_if_present,
                );
                match attempt {
                    Ok(r) => return Ok(r),
                    Err(e) => last_err = Some(e),
                }
            }
            Err(last_err.unwrap_or_else(|| AegisError::CryptoError {
                message: "无法解密（UserPassphrase）".to_string(),
                code: Some(ErrorCode::Console702),
            }))
        }
        Decryption::None => Err(AegisError::ProtocolError {
            message: "decryption=none 不允许进入解密流程".to_string(),
            code: Some(ErrorCode::Console701),
        }),
    }
}

fn decrypt_with_passphrase_and_len(
    bytes: &[u8],
    header: &AesHeader,
    passphrase: &str,
    rsa_ct_len: usize,
    verify_hmac_if_present: bool,
) -> Result<DecryptBuildResult, AegisError> {
    let (user_slot, _rsa_ct, stream) = read_artifact_parts(bytes, rsa_ct_len)?;
    let kek_bytes = crypto::derive_kek_argon2id(passphrase.as_bytes(), header.kdf_salt.as_slice())
        .map_err(map_open_artifact_err)?;
    let kek = Kek::from(kek_bytes);
    let unwrapped = kek
        .unwrap_vec(user_slot)
        .map_err(|e| AegisError::CryptoError {
            message: format!("AES-256-KeyWrap 解密 SessionKey 失败: {e}"),
            code: Some(ErrorCode::Console702),
        })?;
    let session_key: [u8; 32] =
        unwrapped
            .as_slice()
            .try_into()
            .map_err(|_| AegisError::CryptoError {
                message: "User Slot 解出的 SessionKey 长度不是 32 bytes".to_string(),
                code: Some(ErrorCode::Console702),
            })?;

    let mut warnings: Vec<String> = Vec::new();
    let (sealed, stream_data) = verify_and_trim_stream(
        bytes,
        stream,
        &session_key,
        verify_hmac_if_present,
        &mut warnings,
    )?;
    let first = decrypt_first_payload_envelope(stream_data, &session_key)?;
    if !matches!(
        first.payload,
        Some(payload_envelope::Payload::SystemInfo(_))
    ) {
        return Err(AegisError::CryptoError {
            message: "口令解密成功但首个 Chunk 非 SystemInfo".to_string(),
            code: Some(ErrorCode::Crypto003),
        });
    }

    let graph = build_graph_from_stream(header, stream_data, &session_key, &mut warnings)?;

    Ok(DecryptBuildResult {
        sealed,
        warnings,
        graph,
    })
}

fn decrypt_first_payload_envelope(
    stream: &[u8],
    session_key: &[u8; 32],
) -> Result<PayloadEnvelope, AegisError> {
    let (chunk, _) = read_next_chunk(stream, 0)?;
    let plaintext =
        crypto::decrypt(chunk, session_key.as_slice()).map_err(map_open_artifact_err)?;
    PayloadEnvelope::decode(plaintext.as_slice()).map_err(|e| AegisError::CryptoError {
        message: format!("PayloadEnvelope 反序列化失败: {e}"),
        code: Some(ErrorCode::Crypto003),
    })
}

fn verify_and_trim_stream<'a>(
    artifact: &[u8],
    stream: &'a [u8],
    session_key: &[u8; 32],
    verify_hmac_if_present: bool,
    warnings: &mut Vec<String>,
) -> Result<(bool, &'a [u8]), AegisError> {
    let has_trailer = artifact.len() >= crypto::HMAC_SIG_TRAILER_LEN
        && artifact
            .get(
                artifact.len() - crypto::HMAC_SIG_TRAILER_LEN
                    ..artifact.len() - crypto::HMAC_SIG_TRAILER_LEN + crypto::HMAC_SIG_MAGIC.len(),
            )
            .is_some_and(|m| m == crypto::HMAC_SIG_MAGIC.as_slice());

    let sealed = if has_trailer {
        if verify_hmac_if_present {
            let ver = crypto::verify_hmac_sig_trailer_v1(artifact, session_key)
                .map_err(map_open_artifact_err)?;
            match ver {
                crypto::HmacSigVerification::Valid => true,
                crypto::HmacSigVerification::Missing | crypto::HmacSigVerification::Invalid => {
                    return Err(AegisError::CryptoError {
                        message: "HMAC 封签校验失败".to_string(),
                        code: Some(ErrorCode::Crypto003),
                    });
                }
            }
        } else {
            warnings.push("WARN: trailer present but verification skipped".to_string());
            false
        }
    } else {
        warnings.push("WARN: missing trailer seal".to_string());
        false
    };

    let stream_data_end = if has_trailer {
        stream.len().saturating_sub(crypto::HMAC_SIG_TRAILER_LEN)
    } else {
        stream.len()
    };
    let stream_data = stream
        .get(..stream_data_end)
        .ok_or(AegisError::ProtocolError {
            message: "stream_data 越界".to_string(),
            code: Some(ErrorCode::Console701),
        })?;
    Ok((sealed, stream_data))
}

fn parse_rsa_private_key(pem: &str) -> Result<RsaPrivateKey, AegisError> {
    let pkcs8 = RsaPrivateKey::from_pkcs8_pem(pem);
    if let Ok(k) = pkcs8 {
        return Ok(k);
    }
    RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| AegisError::CryptoError {
        message: format!("解析 RSA 私钥失败: {e}"),
        code: Some(ErrorCode::Console702),
    })
}

fn read_artifact_parts(
    artifact: &[u8],
    rsa_ct_len: usize,
) -> Result<ArtifactParts<'_>, AegisError> {
    let user_slot_start = crypto::AES_HEADER_LEN;
    let user_slot_end = user_slot_start + USER_SLOT_LEN;
    let user_slot =
        artifact
            .get(user_slot_start..user_slot_end)
            .ok_or(AegisError::ProtocolError {
                message: "Artifact 长度不足（User slot）".to_string(),
                code: Some(ErrorCode::Console701),
            })?;

    let rsa_start = user_slot_end;
    let rsa_end = rsa_start + rsa_ct_len;
    let rsa_ct = artifact
        .get(rsa_start..rsa_end)
        .ok_or(AegisError::ProtocolError {
            message: "Artifact 长度不足（RSA block）".to_string(),
            code: Some(ErrorCode::Console701),
        })?;

    let stream = artifact.get(rsa_end..).ok_or(AegisError::ProtocolError {
        message: "Artifact 长度不足（stream）".to_string(),
        code: Some(ErrorCode::Console701),
    })?;

    Ok((user_slot, rsa_ct, stream))
}

fn read_next_chunk(stream: &[u8], offset: usize) -> Result<(&[u8], usize), AegisError> {
    if stream.len().saturating_sub(offset) < 24 + 4 + 16 {
        return Err(AegisError::ProtocolError {
            message: "chunk 头部不足".to_string(),
            code: Some(ErrorCode::Console701),
        });
    }
    let len_bytes = stream
        .get(offset + 24..offset + 28)
        .ok_or(AegisError::ProtocolError {
            message: "读取 payload_len 失败".to_string(),
            code: Some(ErrorCode::Console701),
        })?;
    let payload_len =
        u32::from_be_bytes(
            len_bytes
                .try_into()
                .map_err(|_| AegisError::ProtocolError {
                    message: "读取 payload_len 失败".to_string(),
                    code: Some(ErrorCode::Console701),
                })?,
        ) as usize;
    if payload_len > crypto::AES_MAX_PAYLOAD_LEN {
        return Err(AegisError::PacketTooLarge {
            size: payload_len,
            limit: crypto::AES_MAX_PAYLOAD_LEN,
        });
    }
    let chunk_len = 24usize
        .checked_add(4)
        .and_then(|v| v.checked_add(payload_len))
        .and_then(|v| v.checked_add(16))
        .ok_or(AegisError::ProtocolError {
            message: "chunk_len 溢出".to_string(),
            code: Some(ErrorCode::Console701),
        })?;
    let end = offset
        .checked_add(chunk_len)
        .ok_or(AegisError::ProtocolError {
            message: "chunk offset 溢出".to_string(),
            code: Some(ErrorCode::Console701),
        })?;
    let chunk = stream.get(offset..end).ok_or(AegisError::ProtocolError {
        message: "chunk 被截断".to_string(),
        code: Some(ErrorCode::Console701),
    })?;
    Ok((chunk, end))
}

#[derive(Default, Clone)]
struct Graph {
    nodes: BTreeMap<String, GraphNode>,
    edges: Vec<GraphEdge>,
    pid_index: HashMap<u32, Vec<ProcIndex>>,
}

#[derive(Clone)]
struct ProcIndex {
    node_id: String,
    start_time_ms: i64,
    exec_id: u64,
}

struct CaseData {
    sealed: bool,
    warnings: Vec<String>,
    graph: Graph,
    loaded: bool,
}

struct DecryptBuildResult {
    sealed: bool,
    warnings: Vec<String>,
    graph: Graph,
}

fn build_graph_from_stream(
    header: &AesHeader,
    stream: &[u8],
    session_key: &[u8; 32],
    warnings: &mut Vec<String>,
) -> Result<Graph, AegisError> {
    let items = decode_stream_items(stream, session_key, warnings)?;
    validate_system_info(items.as_slice())?;

    let host_uuid = Uuid::from_bytes(header.host_uuid);
    let host_uuid_str = host_uuid.to_string();

    let (processes, files) = collect_payloads(items.as_slice());
    build_graph_from_payloads(
        host_uuid_str.as_str(),
        processes.as_slice(),
        files.as_slice(),
    )
}

fn decode_stream_items(
    stream: &[u8],
    session_key: &[u8; 32],
    warnings: &mut Vec<String>,
) -> Result<Vec<PayloadEnvelope>, AegisError> {
    let mut offset = 0usize;
    let mut items: Vec<PayloadEnvelope> = Vec::new();
    let mut dropped_last = false;

    while offset < stream.len() {
        if stream.len().saturating_sub(offset) < 24 + 4 + 16 {
            dropped_last = true;
            break;
        }

        let (chunk, next) = match read_next_chunk(stream, offset) {
            Ok(v) => v,
            Err(AegisError::ProtocolError { .. }) => {
                dropped_last = true;
                break;
            }
            Err(AegisError::PacketTooLarge { size, limit }) => {
                return Err(AegisError::PacketTooLarge { size, limit });
            }
            Err(e) => return Err(e),
        };
        offset = next;

        let plaintext =
            crypto::decrypt(chunk, session_key.as_slice()).map_err(map_open_artifact_err)?;
        let env =
            PayloadEnvelope::decode(plaintext.as_slice()).map_err(|e| AegisError::CryptoError {
                message: format!("PayloadEnvelope 反序列化失败: {e}"),
                code: Some(ErrorCode::Crypto003),
            })?;
        items.push(env);
    }

    if dropped_last {
        warnings.push("WARN: truncated tail; last incomplete chunk dropped".to_string());
    }

    Ok(items)
}

fn validate_system_info(items: &[PayloadEnvelope]) -> Result<(), AegisError> {
    let Some(first) = items.first() else {
        return Err(AegisError::CryptoError {
            message: "SystemInfo 块缺失或顺序错误".to_string(),
            code: Some(ErrorCode::Crypto003),
        });
    };
    if !matches!(
        first.payload,
        Some(payload_envelope::Payload::SystemInfo(_))
    ) {
        return Err(AegisError::CryptoError {
            message: "SystemInfo 块缺失或顺序错误".to_string(),
            code: Some(ErrorCode::Crypto003),
        });
    }
    Ok(())
}

fn collect_payloads(
    items: &[PayloadEnvelope],
) -> (Vec<ProcessInfo>, Vec<common::protocol::FileInfo>) {
    let mut processes: Vec<ProcessInfo> = Vec::new();
    let mut files: Vec<common::protocol::FileInfo> = Vec::new();

    for env in items {
        match env.payload.as_ref() {
            Some(payload_envelope::Payload::ProcessInfo(p)) => processes.push(p.clone()),
            Some(payload_envelope::Payload::FileInfo(f)) => files.push(f.clone()),
            _ => {}
        }
    }

    (processes, files)
}

fn build_graph_from_payloads(
    host_uuid: &str,
    processes: &[ProcessInfo],
    files: &[common::protocol::FileInfo],
) -> Result<Graph, AegisError> {
    let mut graph = Graph::default();

    for p in processes {
        let mut collision_suffix: Option<u32> = None;
        let mut id = process_node_id(host_uuid, p, collision_suffix);
        let mut suffix = 0u32;
        while graph.nodes.contains_key(id.as_str()) {
            suffix = suffix.saturating_add(1);
            if suffix > 1000 {
                return Err(AegisError::ProtocolError {
                    message: "溯源图构建失败: process node id collision".to_string(),
                    code: Some(ErrorCode::Console711),
                });
            }
            collision_suffix = Some(suffix);
            id = process_node_id(host_uuid, p, collision_suffix);
        }

        let collision_ambiguous = collision_suffix.is_some();
        let node = process_node_with_id(host_uuid, p, id, collision_ambiguous);
        graph.pid_index.entry(p.pid).or_default().push(ProcIndex {
            node_id: node.id.clone(),
            start_time_ms: p.start_time,
            exec_id: p.exec_id,
        });
        graph.nodes.insert(node.id.clone(), node);
    }

    for p in processes {
        if p.ppid == 0 {
            continue;
        }
        let child_id = find_process_node_id(&graph, p.pid, p.start_time, p.exec_id, host_uuid)?;
        let parent = choose_parent_node_id(&graph, p.ppid, p.start_time);
        if let Some(parent_id) = parent {
            graph.edges.push(GraphEdge {
                id: edge_id(parent_id.as_str(), child_id.as_str(), EdgeType::ParentOf),
                src: parent_id,
                dst: child_id,
                r#type: EdgeType::ParentOf,
                confidence: 1.0,
            });
        } else {
            let phantom = phantom_process_node(
                host_uuid,
                p.ppid,
                p.start_time,
                &graph,
                graph.nodes.get(child_id.as_str()),
            )?;
            let phantom_id = phantom.id.clone();
            graph.nodes.insert(phantom.id.clone(), phantom);
            graph.edges.push(GraphEdge {
                id: edge_id(
                    phantom_id.as_str(),
                    child_id.as_str(),
                    EdgeType::InferredLink,
                ),
                src: phantom_id,
                dst: child_id,
                r#type: EdgeType::InferredLink,
                confidence: 0.6,
            });
        }
    }

    for f in files {
        let node = file_node(host_uuid, f);
        graph.nodes.insert(node.id.clone(), node);
    }

    Ok(graph)
}

fn find_process_node_id(
    graph: &Graph,
    pid: u32,
    start_time_ms: i64,
    exec_id: u64,
    _host_uuid: &str,
) -> Result<String, AegisError> {
    if let Some(list) = graph.pid_index.get(&pid)
        && let Some(hit) = list
            .iter()
            .find(|idx| idx.start_time_ms == start_time_ms && idx.exec_id == exec_id)
    {
        return Ok(hit.node_id.clone());
    }
    Err(AegisError::ProtocolError {
        message: "溯源图构建失败: 进程节点缺失".to_string(),
        code: Some(ErrorCode::Console711),
    })
}

fn choose_parent_node_id(graph: &Graph, ppid: u32, child_start_ms: i64) -> Option<String> {
    let list = graph.pid_index.get(&ppid)?;
    let mut best: Option<&ProcIndex> = None;
    for idx in list {
        if idx.start_time_ms <= child_start_ms {
            best = match best {
                None => Some(idx),
                Some(b) => {
                    if idx.start_time_ms > b.start_time_ms {
                        Some(idx)
                    } else {
                        Some(b)
                    }
                }
            };
        }
    }
    best.map(|b| b.node_id.clone())
}

fn process_node_id(host_uuid: &str, p: &ProcessInfo, collision_suffix: Option<u32>) -> String {
    let start_sec = p.start_time / 1000;
    match collision_suffix {
        Some(s) => {
            sha256_hex(format!("{host_uuid}:{}:{start_sec}:{}:_{s}", p.pid, p.exec_id).as_bytes())
        }
        None => sha256_hex(format!("{host_uuid}:{}:{start_sec}:{}", p.pid, p.exec_id).as_bytes()),
    }
}

fn process_node_with_id(
    _host_uuid: &str,
    p: &ProcessInfo,
    id: String,
    collision_ambiguous: bool,
) -> GraphNode {
    let mut tags: Vec<String> = Vec::new();
    let mut attrs: BTreeMap<String, String> = BTreeMap::new();
    attrs.insert("pid".to_string(), p.pid.to_string());
    attrs.insert("ppid".to_string(), p.ppid.to_string());
    attrs.insert("exec_id".to_string(), p.exec_id.to_string());
    attrs.insert("exec_id_quality".to_string(), p.exec_id_quality.clone());
    attrs.insert("start_time_ms".to_string(), p.start_time.to_string());
    if !p.cmdline.is_empty() {
        attrs.insert("cmdline".to_string(), p.cmdline.clone());
    }
    if !p.exe_path.is_empty() {
        attrs.insert("exe_path".to_string(), p.exe_path.clone());
    }
    if p.is_ghost {
        tags.push("Ghosting".to_string());
    }
    if p.is_mismatched {
        tags.push("Mismatched".to_string());
    }
    if p.has_floating_code {
        tags.push("FloatingCode".to_string());
    }
    let ambiguous = collision_ambiguous || p.exec_id_quality.contains("fallback");
    if ambiguous {
        attrs.insert("ambiguous_link".to_string(), "true".to_string());
        tags.push("AmbiguousExecId".to_string());
    }
    let risk = risk_score_process(p, ambiguous);

    GraphNode {
        id,
        label: if p.name.is_empty() {
            format!("pid:{}", p.pid)
        } else {
            p.name.clone()
        },
        r#type: NodeType::Process,
        risk_score: risk,
        is_inferred: false,
        tags,
        attrs,
    }
}

fn phantom_process_node(
    host_uuid: &str,
    pid: u32,
    child_start_time_ms: i64,
    graph: &Graph,
    child: Option<&GraphNode>,
) -> Result<GraphNode, AegisError> {
    let start_sec = (child_start_time_ms / 1000).saturating_sub(1);
    let mut suffix = 0u32;
    let mut id = sha256_hex(format!("{host_uuid}:{pid}:{start_sec}:0").as_bytes());
    while graph.nodes.contains_key(id.as_str()) {
        suffix = suffix.saturating_add(1);
        id = sha256_hex(format!("{host_uuid}:{pid}:{start_sec}:0:_{suffix}").as_bytes());
        if suffix > 1000 {
            return Err(AegisError::ProtocolError {
                message: "溯源图构建失败: phantom node id collision".to_string(),
                code: Some(ErrorCode::Console711),
            });
        }
    }
    let mut tags = vec!["Inferred".to_string()];
    let mut attrs: BTreeMap<String, String> = BTreeMap::new();
    attrs.insert("pid".to_string(), pid.to_string());
    attrs.insert("is_phantom".to_string(), "true".to_string());

    let neighbor_risk = child.map_or(0, |c| c.risk_score);
    let risk = std::cmp::min(neighbor_risk, 80);
    if risk >= 80 {
        tags.push("CriticalPath".to_string());
    }

    Ok(GraphNode {
        id,
        label: format!("phantom_pid:{pid}"),
        r#type: NodeType::Process,
        risk_score: risk,
        is_inferred: true,
        tags,
        attrs,
    })
}

fn file_node(host_uuid: &str, f: &common::protocol::FileInfo) -> GraphNode {
    let event_sec = f.modified / 1000;
    let time_bucket = event_sec / 3600;
    let id = sha256_hex(format!("{host_uuid}:{}:{time_bucket}", f.path).as_bytes());
    let mut tags: Vec<String> = Vec::new();
    let mut attrs: BTreeMap<String, String> = BTreeMap::new();
    attrs.insert("path".to_string(), f.path.clone());
    attrs.insert("size".to_string(), f.size.to_string());
    if f.is_timestomped {
        tags.push("Timestomp".to_string());
    }
    if !f.ads_streams.is_empty() {
        tags.push("ADS".to_string());
        attrs.insert("ads_streams".to_string(), f.ads_streams.join(","));
    }
    if f.is_locked {
        tags.push("Locked".to_string());
    }
    let risk = risk_score_file(f);

    GraphNode {
        id,
        label: f.path.clone(),
        r#type: NodeType::File,
        risk_score: risk,
        is_inferred: false,
        tags,
        attrs,
    }
}

fn risk_score_process(p: &ProcessInfo, ambiguous: bool) -> u32 {
    let mut score: i32 = 10;
    if p.is_ghost {
        score += 80;
    }
    if p.is_mismatched {
        score += 60;
    }
    if p.has_floating_code {
        score += 60;
    }
    if ambiguous {
        score -= 10;
    }
    if score < 0 {
        0
    } else if score > 100 {
        100
    } else {
        u32::try_from(score).unwrap_or(0)
    }
}

fn risk_score_file(f: &common::protocol::FileInfo) -> u32 {
    let mut score: i32 = 5;
    if f.is_timestomped {
        score += 80;
    }
    if !f.ads_streams.is_empty() {
        score += 60;
    }
    if f.is_locked {
        score += 10;
    }
    if score < 0 {
        0
    } else if score > 100 {
        100
    } else {
        u32::try_from(score).unwrap_or(0)
    }
}

fn sha256_hex(input: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    let out = hasher.finalize();
    hex_lower(out.as_slice())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        if write!(s, "{b:02x}").is_err() {}
    }
    s
}

fn edge_id(src: &str, dst: &str, t: EdgeType) -> String {
    let raw = format!("{src}->{dst}:{t:?}");
    sha256_hex(raw.as_bytes())
}

impl PersistenceState {
    fn new(cfg: PersistenceConfig) -> Result<Self, AegisError> {
        let PersistenceConfig { data_dir, db_path } = cfg;

        fs::create_dir_all(data_dir.as_path())
            .map_err(|e| map_console_733(AegisError::IoError(e), "创建 data_dir 失败"))?;
        let cases_dir = data_dir.join("cases");
        fs::create_dir_all(cases_dir.as_path())
            .map_err(|e| map_console_733(AegisError::IoError(e), "创建 cases_dir 失败"))?;

        let rt = Runtime::new()
            .map_err(|e| map_console_733(AegisError::IoError(e), "创建 runtime 失败"))?;
        let options = SqliteConnectOptions::new()
            .filename(db_path.as_path())
            .create_if_missing(true);
        let pool = rt
            .block_on(async {
                SqlitePoolOptions::new()
                    .max_connections(4)
                    .connect_with(options)
                    .await
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("打开 sqlite 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })?;

        let state = Self {
            cases_dir,
            pool,
            rt,
        };
        state.init_db()?;
        Ok(state)
    }

    fn init_db(&self) -> Result<(), AegisError> {
        let now_ms = unix_timestamp_now_ms();
        self.rt
            .block_on(async {
                sqlx::query(
                    r"
CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  request_id INTEGER NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  case_path TEXT,
  bytes_written INTEGER NOT NULL,
  next_sequence_id INTEGER,
  error_message TEXT
);
",
                )
                .execute(&self.pool)
                .await?;

                let alter = sqlx::query(r"ALTER TABLE tasks ADD COLUMN next_sequence_id INTEGER;")
                    .execute(&self.pool)
                    .await;
                if let Err(e) = alter {
                    let msg = e.to_string();
                    if !msg.contains("duplicate column name") && !msg.contains("already exists") {
                        return Err(e);
                    }
                }

                sqlx::query(
                    r"
UPDATE tasks
SET status = 'failed',
    updated_at_ms = ?,
    error_message = COALESCE(error_message, 'console restarted during upload')
WHERE status = 'uploading';
",
                )
                .bind(now_ms)
                .execute(&self.pool)
                .await?;

                Ok::<(), sqlx::Error>(())
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("初始化 sqlite 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })?;
        Ok(())
    }

    fn request_id_exists(&self, request_id: u64) -> Result<bool, AegisError> {
        let row = self
            .rt
            .block_on(async {
                sqlx::query(
                    r"
SELECT 1
FROM tasks
WHERE request_id = ?
LIMIT 1;
",
                )
                .bind(i64::try_from(request_id).unwrap_or(i64::MAX))
                .fetch_optional(&self.pool)
                .await
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("读取 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })?;
        Ok(row.is_some())
    }

    fn insert_task_row(
        &self,
        task_id: &str,
        request_id: u64,
        status: &TaskStatus,
        created_at_ms: i64,
        updated_at_ms: i64,
        case_path: &str,
    ) -> Result<(), AegisError> {
        let status_str = task_status_as_str(status);
        self.rt
            .block_on(async {
                sqlx::query(
                    r"
INSERT INTO tasks (
  task_id,
  request_id,
  status,
  created_at_ms,
  updated_at_ms,
  case_path,
  bytes_written,
  next_sequence_id,
  error_message
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
",
                )
                .bind(task_id)
                .bind(i64::try_from(request_id).unwrap_or(i64::MAX))
                .bind(status_str)
                .bind(created_at_ms)
                .bind(updated_at_ms)
                .bind(case_path)
                .bind(0i64)
                .bind(0i64)
                .bind(Option::<String>::None)
                .execute(&self.pool)
                .await?;
                Ok::<(), sqlx::Error>(())
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("写入 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })
    }

    fn update_task_progress(
        &self,
        task_id: &str,
        status: &TaskStatus,
        updated_at_ms: i64,
        bytes_written: u64,
        next_sequence_id: u64,
    ) -> Result<(), AegisError> {
        let status_str = task_status_as_str(status);
        let bytes_written_i64 = i64::try_from(bytes_written).unwrap_or(i64::MAX);
        let next_sequence_id_i64 = i64::try_from(next_sequence_id).unwrap_or(i64::MAX);
        self.rt
            .block_on(async {
                sqlx::query(
                    r"
UPDATE tasks
SET status = ?,
    updated_at_ms = ?,
    bytes_written = ?,
    next_sequence_id = ?
WHERE task_id = ?;
",
                )
                .bind(status_str)
                .bind(updated_at_ms)
                .bind(bytes_written_i64)
                .bind(next_sequence_id_i64)
                .bind(task_id)
                .execute(&self.pool)
                .await?;
                Ok::<(), sqlx::Error>(())
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("更新 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })
    }

    fn mark_task_failed(
        &self,
        task_id: &str,
        updated_at_ms: i64,
        error_message: &str,
    ) -> Result<(), AegisError> {
        self.rt
            .block_on(async {
                sqlx::query(
                    r"
UPDATE tasks
SET status = 'failed',
    updated_at_ms = ?,
    error_message = ?
WHERE task_id = ?;
",
                )
                .bind(updated_at_ms)
                .bind(error_message)
                .bind(task_id)
                .execute(&self.pool)
                .await?;
                Ok::<(), sqlx::Error>(())
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("更新 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })
    }

    fn mark_task_uploading(
        &self,
        task_id: &str,
        updated_at_ms: i64,
        bytes_written: u64,
        next_sequence_id: u64,
    ) -> Result<(), AegisError> {
        let bytes_written_i64 = i64::try_from(bytes_written).unwrap_or(i64::MAX);
        let next_sequence_id_i64 = i64::try_from(next_sequence_id).unwrap_or(i64::MAX);
        self.rt
            .block_on(async {
                sqlx::query(
                    r"
UPDATE tasks
SET status = 'uploading',
    updated_at_ms = ?,
    bytes_written = ?,
    next_sequence_id = ?,
    error_message = NULL
WHERE task_id = ?;
",
                )
                .bind(updated_at_ms)
                .bind(bytes_written_i64)
                .bind(next_sequence_id_i64)
                .bind(task_id)
                .execute(&self.pool)
                .await?;
                Ok::<(), sqlx::Error>(())
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("更新 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })
    }

    fn get_task_row(&self, task_id: &str) -> Result<Option<GetTaskOutput>, AegisError> {
        self.rt
            .block_on(async {
                let row = sqlx::query(
                    r"
SELECT task_id, status, created_at_ms, updated_at_ms, bytes_written, next_sequence_id, error_message, case_path
FROM tasks
WHERE task_id = ?;
",
                )
                .bind(task_id)
                .fetch_optional(&self.pool)
                .await?;

                let Some(row) = row else {
                    return Ok::<Option<GetTaskOutput>, sqlx::Error>(None);
                };

                let status_str: String = row.try_get("status")?;
                let status =
                    task_status_from_str(status_str.as_str()).unwrap_or(TaskStatus::Failed);
                let bytes_written: i64 = row.try_get("bytes_written")?;
                let bytes_written_u64 = u64::try_from(bytes_written).ok();
                let next_sequence_id: Option<i64> = row.try_get("next_sequence_id").ok();
                let next_sequence_id =
                    next_sequence_id.and_then(|v| u64::try_from(v).ok());
                let error_message: Option<String> = row.try_get("error_message")?;
                let case_path: Option<String> = row.try_get("case_path")?;
                let created_at_ms: i64 = row.try_get("created_at_ms")?;
                let updated_at_ms: i64 = row.try_get("updated_at_ms")?;

                Ok(Some(GetTaskOutput {
                    task_id: task_id.to_string(),
                    status,
                    created_at_ms,
                    updated_at_ms,
                    bytes_written: bytes_written_u64,
                    next_sequence_id,
                    error_message,
                    case_path,
                }))
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("读取 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })
    }

    fn get_task_row_by_request_id(
        &self,
        request_id: u64,
    ) -> Result<Option<GetTaskOutput>, AegisError> {
        let row = self
            .rt
            .block_on(async {
                sqlx::query(
                    r"
SELECT task_id, status, created_at_ms, updated_at_ms, bytes_written, next_sequence_id, error_message, case_path
FROM tasks
WHERE request_id = ?
ORDER BY created_at_ms DESC, task_id DESC
LIMIT 1;
",
                )
                .bind(i64::try_from(request_id).unwrap_or(i64::MAX))
                .fetch_optional(&self.pool)
                .await
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("读取 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })?;
        let Some(row) = row else {
            return Ok(None);
        };
        let task_id: String = row.try_get("task_id").unwrap_or_else(|_| String::new());
        let status_str: String = row
            .try_get("status")
            .unwrap_or_else(|_| "failed".to_string());
        let status = task_status_from_str(status_str.as_str()).unwrap_or(TaskStatus::Failed);
        let bytes_written: i64 = row.try_get("bytes_written").unwrap_or(0);
        let bytes_written_u64 = u64::try_from(bytes_written).ok();
        let next_sequence_id: Option<i64> = row.try_get("next_sequence_id").ok();
        let next_sequence_id = next_sequence_id.and_then(|v| u64::try_from(v).ok());
        let error_message: Option<String> = row.try_get("error_message").unwrap_or(None);
        let case_path: Option<String> = row.try_get("case_path").unwrap_or(None);
        let created_at_ms: i64 = row.try_get("created_at_ms").unwrap_or(0);
        let updated_at_ms: i64 = row.try_get("updated_at_ms").unwrap_or(0);
        Ok(Some(GetTaskOutput {
            task_id,
            status,
            created_at_ms,
            updated_at_ms,
            bytes_written: bytes_written_u64,
            next_sequence_id,
            error_message,
            case_path,
        }))
    }

    fn list_tasks(&self, page: Option<crate::model::Page>) -> Result<ListTasksOutput, AegisError> {
        let cursor = page
            .as_ref()
            .and_then(|p| p.cursor.clone())
            .unwrap_or_else(|| "0".to_string());
        let start: usize = cursor.parse().unwrap_or(0);
        let limit: usize = page
            .and_then(|p| p.limit)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(50)
            .min(200);
        let fetch = limit.saturating_add(1);

        let rows = self
            .rt
            .block_on(async {
                sqlx::query(
                    r"
SELECT task_id, status, created_at_ms, updated_at_ms, bytes_written
FROM tasks
ORDER BY created_at_ms DESC, task_id DESC
LIMIT ? OFFSET ?;
",
                )
                .bind(i64::try_from(fetch).unwrap_or(i64::MAX))
                .bind(i64::try_from(start).unwrap_or(i64::MAX))
                .fetch_all(&self.pool)
                .await
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("读取 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })?;

        let mut tasks: Vec<TaskSummary> = Vec::new();
        for row in rows.iter().take(limit) {
            let task_id: String = row.try_get("task_id").unwrap_or_else(|_| String::new());
            let status_str: String = row
                .try_get("status")
                .unwrap_or_else(|_| "failed".to_string());
            let status = task_status_from_str(status_str.as_str()).unwrap_or(TaskStatus::Failed);
            let created_at_ms: i64 = row.try_get("created_at_ms").unwrap_or(0);
            let updated_at_ms: i64 = row.try_get("updated_at_ms").unwrap_or(0);
            let bytes_written: i64 = row.try_get("bytes_written").unwrap_or(0);
            let bytes_written_u64 = u64::try_from(bytes_written).unwrap_or(0);
            tasks.push(TaskSummary {
                task_id,
                status,
                created_at_ms,
                updated_at_ms,
                bytes_written: bytes_written_u64,
            });
        }

        let next_cursor = if rows.len() > limit {
            Some(start.saturating_add(limit).to_string())
        } else {
            None
        };

        Ok(ListTasksOutput { tasks, next_cursor })
    }

    fn get_case_path_by_task_id(&self, task_id: &str) -> Result<Option<String>, AegisError> {
        let row = self
            .rt
            .block_on(async {
                sqlx::query(
                    r"
SELECT status, case_path
FROM tasks
WHERE task_id = ?;
",
                )
                .bind(task_id)
                .fetch_optional(&self.pool)
                .await
            })
            .map_err(|e| AegisError::ProtocolError {
                message: format!("读取 tasks 失败: {e}"),
                code: Some(ErrorCode::Console733),
            })?;
        let Some(row) = row else {
            return Ok(None);
        };
        let status_str: String = row
            .try_get("status")
            .unwrap_or_else(|_| "failed".to_string());
        let status = task_status_from_str(status_str.as_str()).unwrap_or(TaskStatus::Failed);
        if matches!(status, TaskStatus::Uploading | TaskStatus::Failed) {
            return Err(AegisError::ProtocolError {
                message: "task_id 对应任务不可打开（uploading/failed）".to_string(),
                code: Some(ErrorCode::Console731),
            });
        }
        let case_path: Option<String> = row.try_get("case_path").unwrap_or(None);
        let Some(case_path) = case_path else {
            return Err(AegisError::ProtocolError {
                message: "task_id 对应任务缺少 case_path".to_string(),
                code: Some(ErrorCode::Console733),
            });
        };
        Ok(Some(case_path))
    }

    fn validate_case_path(&self, case_path: &str) -> Result<PathBuf, AegisError> {
        let candidate = PathBuf::from(case_path);
        if !candidate.is_absolute() {
            return Err(AegisError::ProtocolError {
                message: "case_path 非绝对路径".to_string(),
                code: Some(ErrorCode::Console733),
            });
        }
        let root = fs::canonicalize(self.cases_dir.as_path())
            .map_err(|e| map_console_733(AegisError::IoError(e), "读取 cases_dir 失败"))?;
        let resolved = fs::canonicalize(candidate.as_path())
            .map_err(|e| map_console_733(AegisError::IoError(e), "读取 case_path 失败"))?;
        if !resolved.starts_with(root.as_path()) {
            return Err(AegisError::ProtocolError {
                message: "case_path 不在 cases_dir 下".to_string(),
                code: Some(ErrorCode::Console733),
            });
        }
        Ok(resolved)
    }
}

fn task_status_as_str(s: &TaskStatus) -> &'static str {
    match s {
        TaskStatus::Uploading => "uploading",
        TaskStatus::Pending => "pending",
        TaskStatus::Running => "running",
        TaskStatus::Done => "done",
        TaskStatus::Failed => "failed",
    }
}

fn task_status_from_str(s: &str) -> Option<TaskStatus> {
    match s {
        "uploading" => Some(TaskStatus::Uploading),
        "pending" => Some(TaskStatus::Pending),
        "running" => Some(TaskStatus::Running),
        "done" => Some(TaskStatus::Done),
        "failed" => Some(TaskStatus::Failed),
        _ => None,
    }
}

fn unix_timestamp_now_ms() -> i64 {
    let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from("C:\\ProgramData"), PathBuf::from);
        base.join("Aegis")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/var/lib/aegis")
    }
}

fn map_console_731(e: AegisError) -> AegisError {
    match e {
        AegisError::ProtocolError { message, .. } => AegisError::ProtocolError {
            message,
            code: Some(ErrorCode::Console731),
        },
        other => AegisError::ProtocolError {
            message: other.to_string(),
            code: Some(ErrorCode::Console731),
        },
    }
}

fn map_console_733(e: AegisError, context: &str) -> AegisError {
    let msg = match e {
        AegisError::ProtocolError { message, .. } => message,
        other => other.to_string(),
    };
    AegisError::ProtocolError {
        message: format!("{context}: {msg}"),
        code: Some(ErrorCode::Console733),
    }
}
