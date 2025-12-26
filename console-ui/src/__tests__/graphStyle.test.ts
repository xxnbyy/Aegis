import { describe, expect, it } from "vitest";
import { nodeFillColor, nodeStrokeDash } from "../utils/graphStyle";
import type { GraphNode } from "../api/types";

describe("nodeStrokeDash", () => {
  it("returns dash pattern for inferred nodes", () => {
    const n: GraphNode = {
      id: "n1",
      label: "x",
      type: "Process",
      risk_score: 90,
      is_inferred: true,
      tags: [],
      attrs: {}
    };
    expect(nodeStrokeDash(n)).toEqual([4, 4]);
  });

  it("returns null for non-inferred nodes", () => {
    const n: GraphNode = {
      id: "n1",
      label: "x",
      type: "Process",
      risk_score: 10,
      is_inferred: false,
      tags: [],
      attrs: {}
    };
    expect(nodeStrokeDash(n)).toBeNull();
  });
});

describe("nodeFillColor", () => {
  it("returns gray for dismissed nodes", () => {
    const n: GraphNode = {
      id: "n1",
      label: "x",
      type: "Process",
      risk_score: 90,
      is_inferred: false,
      tags: [],
      attrs: {}
    };
    expect(nodeFillColor(n, { dismissed: true })).toBe("#9ca3af");
  });

  it("returns green for true positive nodes", () => {
    const n: GraphNode = {
      id: "n1",
      label: "x",
      type: "Process",
      risk_score: 10,
      is_inferred: false,
      tags: [],
      attrs: {}
    };
    expect(nodeFillColor(n, { truePositive: true })).toBe("#16a34a");
  });
});
