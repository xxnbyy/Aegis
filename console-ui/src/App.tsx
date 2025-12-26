import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import { AegisClient } from "./api/aegisClient";
import type {
  AiInsight,
  GraphEdge,
  GraphNode,
  OpenArtifactOutput,
  ProbeStatus,
  ProbeTelemetry,
  TaskSummary,
  WsEnvelope
} from "./api/types";
import CopyCommandModal from "./components/CopyCommandModal";
import { nodeFillColor, nodeStrokeDash } from "./utils/graphStyle";
import { isMobileUserAgent } from "./utils/ua";

type GraphData = { nodes: GraphNode[]; links: GraphEdge[] };

const DEFAULT_BASE_URL = "http://127.0.0.1:8080";

function envBaseUrl(): string {
  const v = (import.meta as any).env?.VITE_AEGIS_CONSOLE_URL as string | undefined;
  return (v && v.trim()) || DEFAULT_BASE_URL;
}

function envSecurityMode(): "secure" | "unsandboxed" {
  const v = (import.meta as any).env?.VITE_AEGIS_SECURITY_MODE as string | undefined;
  return v?.trim().toLowerCase() === "unsandboxed" ? "unsandboxed" : "secure";
}

function envNativePlugins(): string[] {
  const v = (import.meta as any).env?.VITE_AEGIS_NATIVE_PLUGINS as string | undefined;
  if (!v) return [];
  return v
    .split(/[\r\n,]+/g)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export default function App() {
  const baseUrl = useMemo(() => envBaseUrl(), []);
  const client = useMemo(() => new AegisClient(baseUrl), [baseUrl]);
  const isMobile = useMemo(() => isMobileUserAgent(navigator.userAgent), []);
  const securityMode = useMemo(() => envSecurityMode(), []);
  const nativePlugins = useMemo(() => envNativePlugins(), []);

  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const [taskId, setTaskId] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [aiKey, setAiKey] = useState("");

  const [tasks, setTasks] = useState<TaskSummary[]>([]);
  const [caseOut, setCaseOut] = useState<OpenArtifactOutput | null>(null);
  const [graph, setGraph] = useState<GraphData>({ nodes: [], links: [] });
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [aiInsight, setAiInsight] = useState<AiInsight | null>(null);

  const [dismissedNodeIds, setDismissedNodeIds] = useState<Record<string, true>>({});
  const [truePositiveNodeIds, setTruePositiveNodeIds] = useState<Record<string, true>>({});

  const [probeTelemetry, setProbeTelemetry] = useState<ProbeTelemetry | null>(null);
  const [probeStatus, setProbeStatus] = useState<ProbeStatus | null>(null);
  const [events, setEvents] = useState<string[]>([]);

  const [copyOpen, setCopyOpen] = useState(false);
  const [nativePluginsOpen, setNativePluginsOpen] = useState(false);

  useEffect(() => {
    let alive = true;
    client
      .listTasks({ page: { limit: 20 } })
      .then((out) => {
        if (!alive) return;
        setTasks(out.tasks ?? []);
      })
      .catch(() => {
        if (!alive) return;
        setTasks([]);
      });
    return () => {
      alive = false;
    };
  }, [client]);

  useEffect(() => {
    const ws = client.connectWs(
      (msg) => onWsMessage(msg),
      () => setWsConnected(false)
    );
    wsRef.current = ws;
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [client]);

  useEffect(() => {
    return () => {
      if (caseOut?.case_id) {
        client.closeCase(caseOut.case_id).catch(() => {});
      }
    };
  }, [client, caseOut?.case_id]);

  function pushEvent(line: string) {
    setEvents((prev) => [line, ...prev].slice(0, 30));
  }

  function onWsMessage(msg: WsEnvelope) {
    if (msg.channel === "probe:telemetry") {
      setProbeTelemetry(msg.payload as ProbeTelemetry);
      return;
    }
    if (msg.channel === "probe:status") {
      setProbeStatus(msg.payload as ProbeStatus);
      return;
    }
    pushEvent(`${msg.channel}: ${JSON.stringify(msg.payload)}`);
  }

  async function openByTaskId(id: string) {
    setAiInsight(null);
    setSelectedNode(null);
    setGraph({ nodes: [], links: [] });
    setDismissedNodeIds({});
    setTruePositiveNodeIds({});
    const out = await client.openArtifact({
      source: { kind: "task_id", task_id: id },
      decryption: passphrase.trim()
        ? { kind: "user_passphrase", passphrase: passphrase.trim() }
        : { kind: "none" },
      options: { verify_hmac_if_present: true }
    });
    setCaseOut(out);
    const v = await client.getGraphViewport({
      case_id: out.case_id,
      level: 0,
      risk_score_threshold: 80
    });
    setGraph({ nodes: v.nodes, links: v.edges });
    pushEvent(`open_artifact ok: case_id=${out.case_id}`);
  }

  async function fetchLevel1(node: GraphNode) {
    if (!caseOut?.case_id) return;
    const v = await client.getGraphViewport({
      case_id: caseOut.case_id,
      level: 1,
      center_node_id: node.id
    });
    const nodeMap = new Map<string, GraphNode>();
    for (const n of [...graph.nodes, ...v.nodes]) {
      nodeMap.set(n.id, n);
    }
    const edgeMap = new Map<string, GraphEdge>();
    for (const e of [...graph.links, ...v.edges]) {
      edgeMap.set(e.id, e);
    }
    setGraph({ nodes: Array.from(nodeMap.values()), links: Array.from(edgeMap.values()) });
  }

  async function loadAiInsight(node?: GraphNode) {
    if (!caseOut?.case_id) return;
    const out = await client.getAiInsight(
      { case_id: caseOut.case_id, node_id: node?.id },
      aiKey.trim() ? aiKey.trim() : undefined
    );
    setAiInsight(out.insight);
  }

  function selectedCommand(): string {
    const cmd = aiInsight?.suggested_mitigation_cmd ?? "";
    return cmd ?? "";
  }

  function markSelectedTruePositive() {
    if (!selectedNode) return;
    const id = selectedNode.id;
    setTruePositiveNodeIds((prev) => ({ ...prev, [id]: true }));
    setDismissedNodeIds((prev) => {
      if (!prev[id]) return prev;
      const next = { ...prev };
      delete next[id];
      return next;
    });
    pushEvent(`review: true_positive node=${id}`);
  }

  function dismissSelectedNode() {
    if (!selectedNode) return;
    const id = selectedNode.id;
    setDismissedNodeIds((prev) => ({ ...prev, [id]: true }));
    setTruePositiveNodeIds((prev) => {
      if (!prev[id]) return prev;
      const next = { ...prev };
      delete next[id];
      return next;
    });
    pushEvent(`review: dismissed node=${id}`);
  }

  const truePositiveIds = useMemo(() => Object.keys(truePositiveNodeIds), [truePositiveNodeIds]);
  const dismissedIds = useMemo(() => Object.keys(dismissedNodeIds), [dismissedNodeIds]);

  function clearReviewMarks() {
    setDismissedNodeIds({});
    setTruePositiveNodeIds({});
    pushEvent("review: cleared");
  }

  return (
    <div className="app">
      <div className="topbar">
        <div className="left">
          <strong>Aegis Console UI (Phase 3.4)</strong>
          <span className={`badge ${securityMode}`}>
            {securityMode === "secure" ? "🟢 SECURE" : "🔴 UNSANDBOXED"}
          </span>
          <span className="badge">{wsConnected ? "WS: connected" : "WS: disconnected"}</span>
        </div>
        <div className="muted">{baseUrl}</div>
      </div>

      {securityMode === "unsandboxed" ? (
        <div
          className="banner"
          role="button"
          tabIndex={0}
          onClick={() => setNativePluginsOpen(true)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              setNativePluginsOpen(true);
            }
          }}
          style={{ borderRadius: 0 }}
        >
          Native plugins loaded. System integrity not guaranteed.
        </div>
      ) : null}

      <div className="content">
        <div className="panel">
          <h2>会话</h2>
          {isMobile ? (
            <div className="banner">Read-Only View. Please use Desktop for actions.</div>
          ) : null}
          <div className="stack" style={{ marginTop: 10 }}>
            <div className="stack">
              <div className="muted">打开已上传证据（task_id）</div>
              <div className="row">
                <input
                  className="input"
                  value={taskId}
                  onChange={(e) => setTaskId(e.target.value)}
                  placeholder="task_id"
                />
                <button
                  className="btn"
                  onClick={() => openByTaskId(taskId.trim())}
                  disabled={isMobile || !taskId.trim()}
                >
                  Open
                </button>
              </div>
              <input
                className="input"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="passphrase (可选；为空则仅 header)"
                type="password"
                disabled={isMobile}
              />
            </div>

            <div className="stack">
              <div className="muted">最近任务</div>
              <ul className="log" aria-label="tasks">
                {tasks.map((t) => (
                  <li key={t.task_id}>
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <span>{t.task_id}</span>
                      <button
                        className="btn secondary"
                        onClick={() => openByTaskId(t.task_id)}
                        disabled={isMobile}
                      >
                        Open
                      </button>
                    </div>
                    <div className="muted">
                      {t.status} · bytes={t.bytes_written}
                    </div>
                  </li>
                ))}
              </ul>
            </div>

            <div className="stack">
              <div className="muted">Probe 事件</div>
              <div className="muted">
                telemetry:{" "}
                {probeTelemetry
                  ? `cpu=${probeTelemetry.cpu_usage_percent}% mem=${probeTelemetry.memory_usage_mb}MB dropped=${probeTelemetry.dropped_events_count}`
                  : "—"}
              </div>
              <div className="muted">
                status:{" "}
                {probeStatus
                  ? `${probeStatus.status} drop_rate=${probeStatus.drop_rate_percent}% dropped=${probeStatus.dropped_events_count}`
                  : "—"}
              </div>
            </div>
          </div>
        </div>

        <div className="graphWrap" aria-label="graph">
          <ForceGraph2D
            graphData={graph as any}
            linkSource="src"
            linkTarget="dst"
            nodeId="id"
            nodeLabel={(n: any) => `${n.label} (${n.risk_score})`}
            nodeCanvasObject={(node: any, ctx, globalScale) => {
              const n = node as GraphNode & { x: number; y: number };
              const label = n.label || n.id;
              const radius = 6;
              const inferred = Boolean(n.is_inferred);
              const alpha = inferred ? 0.5 : 1;

              ctx.save();
              ctx.globalAlpha = alpha;
              ctx.beginPath();
              ctx.fillStyle = nodeFillColor(n, {
                dismissed: Boolean(dismissedNodeIds[n.id]),
                truePositive: Boolean(truePositiveNodeIds[n.id])
              });
              ctx.arc(n.x, n.y, radius, 0, 2 * Math.PI);
              ctx.fill();

              ctx.lineWidth = 2 / globalScale;
              ctx.strokeStyle = "#111827";
              const dash = nodeStrokeDash(n);
              ctx.setLineDash(dash ?? []);
              ctx.beginPath();
              ctx.arc(n.x, n.y, radius + 2 / globalScale, 0, 2 * Math.PI);
              ctx.stroke();
              ctx.setLineDash([]);

              const fontSize = 12 / globalScale;
              ctx.font = `${fontSize}px sans-serif`;
              ctx.fillStyle = "#111827";
              ctx.textAlign = "left";
              ctx.textBaseline = "middle";
              ctx.fillText(label, n.x + (radius + 6) / globalScale, n.y);
              ctx.restore();
            }}
            onNodeClick={async (node: any) => {
              const n = node as GraphNode;
              setSelectedNode(n);
              if (isMobile) return;
              await fetchLevel1(n).catch(() => {});
              await loadAiInsight(n).catch(() => {});
            }}
          />
        </div>

        <div className="panel">
          <h2>AI Insight</h2>
          <div className="stack">
            <div className="row">
              <input
                className="input"
                value={aiKey}
                onChange={(e) => setAiKey(e.target.value)}
                placeholder="X-Aegis-AI-Key（可选；覆盖后端环境变量）"
                type="password"
                disabled={isMobile}
              />
              <button
                className="btn secondary"
                onClick={() => loadAiInsight(selectedNode ?? undefined)}
                disabled={isMobile || !caseOut?.case_id}
              >
                Refresh
              </button>
            </div>

            {aiInsight ? (
              <>
                <div className="muted">
                  {aiInsight.risk_level} · score={aiInsight.risk_score} · risky=
                  {String(aiInsight.is_risky)} · suggestion={String(aiInsight.is_suggestion)}
                </div>
                <div>{aiInsight.summary}</div>
                {aiInsight.technique ? <div className="muted">technique: {aiInsight.technique}</div> : null}
                {!isMobile ? (
                  <div className="row" style={{ marginTop: 6 }}>
                    <button className="btn" onClick={markSelectedTruePositive} disabled={!selectedNode}>
                      ✅ Mark as True Positive
                    </button>
                    <button className="btn secondary" onClick={dismissSelectedNode} disabled={!selectedNode}>
                      🚫 Dismiss
                    </button>
                  </div>
                ) : null}
                {!isMobile ? (
                  <div className="stack" style={{ marginTop: 8 }}>
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <div className="muted">
                        review: true_positive={truePositiveIds.length} · dismissed={dismissedIds.length}
                      </div>
                      <button className="btn secondary" onClick={clearReviewMarks}>
                        Clear
                      </button>
                    </div>
                    {truePositiveIds.length > 0 ? (
                      <div className="code">{truePositiveIds.join("\n")}</div>
                    ) : null}
                    {dismissedIds.length > 0 ? (
                      <div className="code">{dismissedIds.join("\n")}</div>
                    ) : null}
                  </div>
                ) : null}
                {aiInsight.suggested_mitigation_cmd ? (
                  <>
                    <div className="muted">suggested_mitigation_cmd</div>
                    <div className="code">{aiInsight.suggested_mitigation_cmd}</div>
                    {isMobile ? (
                      <div className="muted danger">移动端已禁用剪贴板写入</div>
                    ) : (
                      <button
                        className="btn"
                        onClick={() => setCopyOpen(true)}
                        disabled={!selectedCommand().trim()}
                      >
                        📋 Copy Command
                      </button>
                    )}
                  </>
                ) : (
                  <div className="muted">该节点暂无可复制命令建议</div>
                )}
              </>
            ) : (
              <div className="muted">点击图中节点以生成 AI 建议（仅建议，不自动执行）</div>
            )}

            <CopyCommandModal
              open={copyOpen}
              command={selectedCommand()}
              onClose={() => setCopyOpen(false)}
              onCopied={() => pushEvent("clipboard: writeText ok")}
            />

            {nativePluginsOpen ? (
              <div className="modalOverlay" role="dialog" aria-modal="true">
                <div className="modal">
                  <h3>Native Plugins</h3>
                  <div className="muted">VITE_AEGIS_NATIVE_PLUGINS</div>
                  <div className="code">
                    {nativePlugins.length > 0 ? nativePlugins.join("\n") : "No native plugin list provided."}
                  </div>
                  <div className="row" style={{ justifyContent: "flex-end", marginTop: 10 }}>
                    <button className="btn secondary" onClick={() => setNativePluginsOpen(false)}>
                      Close
                    </button>
                  </div>
                </div>
              </div>
            ) : null}

            <div className="stack" style={{ marginTop: 10 }}>
              <div className="muted">事件流（最近 30 条）</div>
              <ul className="log" aria-label="events">
                {events.map((e, idx) => (
                  <li key={`${idx}-${e}`}>{e}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
