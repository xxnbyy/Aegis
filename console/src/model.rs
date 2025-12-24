use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenArtifactInput {
    pub source: Source,
    pub decryption: Decryption,
    pub options: OpenArtifactOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenArtifactOptions {
    pub verify_hmac_if_present: bool,
}

impl Default for OpenArtifactOptions {
    fn default() -> Self {
        Self {
            verify_hmac_if_present: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    LocalPath { path: String },
    TaskId { task_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decryption {
    UserPassphrase { passphrase: String },
    OrgPrivateKeyPem { pem: String },
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenArtifactOutput {
    pub case_id: String,
    pub host_uuid: String,
    pub org_key_fp: String,
    pub sealed: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetGraphViewportInput {
    pub case_id: String,
    pub level: ViewportLevel,
    pub viewport_bbox: Option<BBox>,
    pub risk_score_threshold: Option<u32>,
    pub center_node_id: Option<String>,
    pub page: Option<Page>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Page {
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewportLevel {
    L0,
    L1,
    L2,
}

impl Serialize for ViewportLevel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ViewportLevel::L0 => serializer.serialize_u8(0),
            ViewportLevel::L1 => serializer.serialize_u8(1),
            ViewportLevel::L2 => serializer.serialize_u8(2),
        }
    }
}

impl<'de> Deserialize<'de> for ViewportLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;

        impl Visitor<'_> for V {
            type Value = ViewportLevel;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("0/1/2 or L0/L1/L2")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                match v {
                    0 => Ok(ViewportLevel::L0),
                    1 => Ok(ViewportLevel::L1),
                    2 => Ok(ViewportLevel::L2),
                    _ => Err(E::custom("invalid viewport level")),
                }
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                self.visit_u64(u64::try_from(v).map_err(|_| E::custom("invalid viewport level"))?)
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match v {
                    "0" | "L0" | "l0" => Ok(ViewportLevel::L0),
                    "1" | "L1" | "l1" => Ok(ViewportLevel::L1),
                    "2" | "L2" | "l2" => Ok(ViewportLevel::L2),
                    _ => Err(E::custom("invalid viewport level")),
                }
            }
        }

        deserializer.deserialize_any(V)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GetGraphViewportOutput {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub next_cursor: Option<String>,
    pub warnings: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BBox {
    pub x1: f64,
    pub y1: f64,
    pub x2: f64,
    pub y2: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NodeType {
    Process,
    File,
    Socket,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub r#type: NodeType,
    pub risk_score: u32,
    pub is_inferred: bool,
    pub tags: Vec<String>,
    pub attrs: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeType {
    ParentOf,
    TouchesFile,
    HasIp,
    TriggeredBy,
    InferredLink,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphEdge {
    pub id: String,
    pub src: String,
    pub dst: String,
    pub r#type: EdgeType,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloseCaseOutput {
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Uploading,
    Pending,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalyzeEvidenceMeta {
    pub filename: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalyzeEvidenceChunkInput {
    pub request_id: u64,
    pub sequence_id: u64,
    pub is_last: bool,
    pub bytes: Vec<u8>,
    pub meta: Option<AnalyzeEvidenceMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalyzeEvidenceOutput {
    pub task_id: String,
    pub status: TaskStatus,
    pub bytes_written: Option<u64>,
    pub next_sequence_id: Option<u64>,
    pub case_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetTaskInput {
    pub task_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetTaskOutput {
    pub task_id: String,
    pub status: TaskStatus,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub bytes_written: Option<u64>,
    pub next_sequence_id: Option<u64>,
    pub error_message: Option<String>,
    pub case_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskSummary {
    pub task_id: String,
    pub status: TaskStatus,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub bytes_written: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListTasksInput {
    pub page: Option<Page>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListTasksOutput {
    pub tasks: Vec<TaskSummary>,
    pub next_cursor: Option<String>,
}
