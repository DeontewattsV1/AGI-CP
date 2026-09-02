import type { CapabilityDecision } from "./types.ts";

export function combineDecisions(decisions: CapabilityDecision[]): CapabilityDecision {
  if (decisions.includes("DENY")) return "DENY";
  if (decisions.includes("INDETERMINATE")) return "INDETERMINATE";
  if (decisions.length > 0 && decisions.every((d) => d === "ALLOW")) return "ALLOW";
  return "INDETERMINATE";
}
