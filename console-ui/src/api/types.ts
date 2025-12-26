export type ViewportLevel = 0 | 1 | 2;

export type Source =
  | { kind: "local_path"; path: string }
  | { kind: "task_id"; task_id: string };

export type Decryption =
  | { kind: "user_passphrase"; passphrase: string }
  | { kind: "org_private_key_pem"; pem: string }
  | { kind: "none" };

export type OpenArtifactOptions = { verify_hmac_if_present: boolean };

export type OpenArtifactInput = {
  source: Source;
  decryption: Decryption;
  options: OpenArtifactOptions;
};

export type OpenArtifactOutput = {
  case_id: string;
  host_uuid: string;
  org_key_fp: string;
  sealed: boolean;
  warnings: string[];
};

export type BBox = { x1: number; y1: number; x2: number; y2: number };

export type Page = { cursor?: string; limit?: number };

export type GetGraphViewportInput = {
  case_id: string;
  level: ViewportLevel;
  viewport_bbox?: BBox;
  risk_score_threshold?: number;
  center_node_id?: string;
  page?: Page;
};

export type NodeType = "Process" | "File" | "Socket";
export type EdgeType = "ParentOf" | "TouchesFile" | "HasIp" | "TriggeredBy" | "InferredLink";

export type GraphNode = {
  id: string;
  label: string;
  type: NodeType;
  risk_score: number;
  is_inferred: boolean;
  tags: string[];
  attrs: Record<string, string>;
};

export type GraphEdge = {
  id: string;
  src: string;
  dst: string;
  type: EdgeType;
  confidence: number;
};

export type GetGraphViewportOutput = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  next_cursor?: string | null;
  warnings?: string[] | null;
};

export type TaskSummary = {
  task_id: string;
  status: "uploading" | "pending" | "running" | "done" | "failed";
  created_at_ms: number;
  updated_at_ms: number;
  bytes_written: number;
};

export type ListTasksInput = { page?: { cursor?: string; limit?: number } };
export type ListTasksOutput = { tasks: TaskSummary[]; next_cursor?: string | null };

export type AiContext = { max_chars?: number };
export type GetAiInsightInput = { case_id: string; node_id?: string; context?: AiContext };

export type AiInsight = {
  summary: string;
  risk_score: number;
  risk_level: string;
  technique?: string | null;
  is_suggestion: boolean;
  is_risky: boolean;
  suggested_mitigation_cmd?: string | null;
  provider?: string | null;
  model?: string | null;
};

export type GetAiInsightOutput = { case_id: string; insight: AiInsight; warnings?: string[] | null };

export type WsEnvelope = { channel: string; payload: unknown };

export type ProbeTelemetry = {
  timestamp: number;
  cpu_usage_percent: number;
  memory_usage_mb: number;
  dropped_events_count: number;
};

export type ProbeStatus = {
  status: string;
  dropped_events_count: number;
  drop_rate_percent: number;
};

