import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

let graphProps: any = null;

vi.mock("react-force-graph-2d", () => {
  return {
    default: (props: any) => {
      graphProps = props;
      return <div aria-label="force-graph" />;
    }
  };
});

vi.mock("../api/aegisClient", () => {
  class WsStub {
    onopen: null | (() => void) = null;
    onclose: null | (() => void) = null;
    close() {}
  }

  class AegisClient {
    constructor(_baseUrl: string) {}

    connectWs(_onMessage: any, _onClose: any) {
      return new WsStub() as any;
    }

    async listTasks() {
      return {
        tasks: [
          {
            task_id: "t1",
            status: "done",
            created_at_ms: 0,
            updated_at_ms: 0,
            bytes_written: 1
          }
        ]
      };
    }

    async openArtifact() {
      return {
        case_id: "case1",
        host_uuid: "h1",
        org_key_fp: "00",
        sealed: true,
        warnings: []
      };
    }

    async getGraphViewport(input: any) {
      if (input.level === 0) {
        return {
          nodes: [
            {
              id: "n1",
              label: "proc",
              type: "Process",
              risk_score: 90,
              is_inferred: false,
              tags: [],
              attrs: {}
            }
          ],
          edges: []
        };
      }
      return {
        nodes: [],
        edges: []
      };
    }

    async getAiInsight() {
      return {
        case_id: "case1",
        insight: {
          summary: "summary-1",
          risk_score: 90,
          risk_level: "HIGH",
          is_suggestion: true,
          is_risky: false,
          suggested_mitigation_cmd: null
        }
      };
    }

    async closeCase() {
      return { ok: true };
    }
  }

  return { AegisClient };
});

function setUserAgent(ua: string) {
  Object.defineProperty(navigator, "userAgent", { value: ua, configurable: true });
}

function fakeCtx() {
  const fillStyles: string[] = [];
  const ctx: any = {
    save: vi.fn(),
    restore: vi.fn(),
    beginPath: vi.fn(),
    arc: vi.fn(),
    fill: vi.fn(),
    stroke: vi.fn(),
    fillText: vi.fn(),
    setLineDash: vi.fn(),
    set globalAlpha(_v: number) {},
    set lineWidth(_v: number) {},
    set strokeStyle(_v: string) {},
    set font(_v: string) {},
    set textAlign(_v: string) {},
    set textBaseline(_v: string) {},
    set fillStyle(v: string) {
      fillStyles.push(v);
    },
    get fillStyle() {
      return fillStyles[fillStyles.length - 1];
    }
  };
  return { ctx, fillStyles };
}

describe("AI Insight actions", () => {
  it("marks dismissed/true positive and affects node fill color", async () => {
    setUserAgent(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    );

    const App = (await import("../App")).default;
    render(<App />);

    await screen.findByText("t1");
    const openButtons = screen.getAllByRole("button", { name: "Open" });
    const btn = openButtons.find((b) => !(b as HTMLButtonElement).disabled);
    expect(btn).toBeTruthy();
    fireEvent.click(btn as HTMLButtonElement);

    await vi.waitFor(() => {
      expect(graphProps?.graphData?.nodes?.length).toBeGreaterThan(0);
    });

    const node = graphProps.graphData.nodes[0];
    await graphProps.onNodeClick(node);

    await screen.findByText("summary-1");

    fireEvent.click(screen.getByRole("button", { name: "🚫 Dismiss" }));
    await screen.findByText("review: dismissed node=n1");

    await vi.waitFor(() => {
      const { ctx, fillStyles } = fakeCtx();
      graphProps.nodeCanvasObject({ ...node, x: 1, y: 2 }, ctx, 1);
      expect(fillStyles[0]).toBe("#9ca3af");
    });

    fireEvent.click(screen.getByRole("button", { name: "✅ Mark as True Positive" }));
    await screen.findByText("review: true_positive node=n1");

    await vi.waitFor(() => {
      const { ctx, fillStyles } = fakeCtx();
      graphProps.nodeCanvasObject({ ...node, x: 1, y: 2 }, ctx, 1);
      expect(fillStyles[0]).toBe("#16a34a");
    });
  });
});
