import type {
  GetAiInsightInput,
  GetAiInsightOutput,
  GetGraphViewportInput,
  GetGraphViewportOutput,
  ListTasksInput,
  ListTasksOutput,
  OpenArtifactInput,
  OpenArtifactOutput,
  WsEnvelope
} from "./types";

export class AegisClient {
  private readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  async healthz(): Promise<string> {
    const r = await fetch(`${this.baseUrl}/healthz`);
    if (!r.ok) {
      throw new Error(`healthz failed: ${r.status}`);
    }
    return r.text();
  }

  async openArtifact(input: OpenArtifactInput): Promise<OpenArtifactOutput> {
    return this.postJson(`/api/v1/open_artifact`, input);
  }

  async getGraphViewport(input: GetGraphViewportInput): Promise<GetGraphViewportOutput> {
    return this.postJson(`/api/v1/get_graph_viewport`, input);
  }

  async closeCase(caseId: string): Promise<{ ok: boolean }> {
    return this.postJson(`/api/v1/close_case/${encodeURIComponent(caseId)}`, {});
  }

  async listTasks(input: ListTasksInput): Promise<ListTasksOutput> {
    return this.postJson(`/api/v1/list_tasks`, input);
  }

  async getAiInsight(input: GetAiInsightInput, aiKey?: string): Promise<GetAiInsightOutput> {
    return this.postJson(`/api/v1/get_ai_insight`, input, aiKey ? { "x-aegis-ai-key": aiKey } : {});
  }

  connectWs(onMessage: (msg: WsEnvelope) => void, onError?: (e: Event) => void): WebSocket {
    const wsUrl = this.baseUrl.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
    const ws = new WebSocket(`${wsUrl}/api/v1/ws`);
    ws.onmessage = (ev) => {
      try {
        const obj = JSON.parse(String(ev.data)) as WsEnvelope;
        if (obj && typeof obj.channel === "string") {
          onMessage(obj);
        }
      } catch {
        return;
      }
    };
    if (onError) {
      ws.onerror = onError;
    }
    return ws;
  }

  private async postJson<T>(path: string, body: unknown, headers?: Record<string, string>): Promise<T> {
    const r = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(headers ?? {})
      },
      body: JSON.stringify(body)
    });
    if (!r.ok) {
      const text = await r.text().catch(() => "");
      throw new Error(`request failed: ${r.status} ${text}`);
    }
    return (await r.json()) as T;
  }
}

