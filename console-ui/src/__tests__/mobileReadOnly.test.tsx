import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("react-force-graph-2d", () => {
  return { default: () => <div aria-label="force-graph" /> };
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
      return { tasks: [{ task_id: "t1", status: "done", bytes_written: 1 }] };
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

describe("mobile read-only", () => {
  it("disables operation buttons and shows banner on mobile", async () => {
    setUserAgent(
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
    );

    const App = (await import("../App")).default;
    render(<App />);

    expect(
      screen.getByText("Read-Only View. Please use Desktop for actions.")
    ).toBeInTheDocument();

    const openButtons = await screen.findAllByRole("button", { name: "Open" });
    for (const btn of openButtons) {
      expect(btn).toBeDisabled();
    }

    expect(screen.getByRole("button", { name: "Refresh" })).toBeDisabled();
    expect(
      screen.getByPlaceholderText("X-Aegis-AI-Key（可选；覆盖后端环境变量）")
    ).toBeDisabled();
  });
});
