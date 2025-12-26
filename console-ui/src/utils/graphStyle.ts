import type { GraphNode } from "../api/types";

export function riskColor(score: number): string {
  const clamped = Math.max(0, Math.min(100, score));
  if (clamped <= 50) {
    const t = clamped / 50;
    const r = Math.round(59 + t * (234 - 59));
    const g = Math.round(130 + t * (179 - 130));
    const b = Math.round(246 + t * (8 - 246));
    return `rgb(${r},${g},${b})`;
  }
  const t = (clamped - 50) / 50;
  const r = Math.round(234 + t * (220 - 234));
  const g = Math.round(179 + t * (38 - 179));
  const b = Math.round(8 + t * (38 - 8));
  return `rgb(${r},${g},${b})`;
}

export function nodeStrokeDash(node: GraphNode): number[] | null {
  return node.is_inferred ? [4, 4] : null;
}

export function nodeFillColor(
  node: GraphNode,
  opts?: { dismissed?: boolean; truePositive?: boolean }
): string {
  if (opts?.dismissed) {
    return "#9ca3af";
  }
  if (opts?.truePositive) {
    return "#16a34a";
  }
  return riskColor(node.risk_score);
}
