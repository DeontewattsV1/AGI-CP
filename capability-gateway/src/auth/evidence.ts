export type EpistemicState =
  | "SATISFIED"
  | "FAILED"
  | "UNKNOWN"
  | "STALE"
  | "CONFLICTING"
  | "UNVERIFIABLE";

export interface Observation {
  observerId: string;
  requestId: string;
  observedAt: number;
  state: Exclude<EpistemicState, "UNVERIFIABLE">;
}

export interface EvidenceWindow {
  requestId: string;
  start: number;
  end: number;
  expectedObserverIds: string[];
}

export interface EvidenceSlot {
  observerId: string;
  state: EpistemicState;
  observation?: Observation;
}

export type EvidenceFailure = "EVIDENCE_FAILED" | "EVIDENCE_UNVERIFIABLE";

export function collectEvidence(
  window: EvidenceWindow,
  observations: Observation[],
): EvidenceSlot[] {
  const inWindow = observations.filter(
    (o) =>
      o.requestId === window.requestId &&
      o.observedAt >= window.start &&
      o.observedAt <= window.end,
  );

  return window.expectedObserverIds.map((observerId) => {
    const matches = inWindow.filter((o) => o.observerId === observerId);
    if (matches.length === 0) {
      return { observerId, state: "UNVERIFIABLE" };
    }
    if (matches.some((o) => o.state === "FAILED")) {
      return { observerId, state: "FAILED", observation: matches[0] };
    }
    if (matches.length > 1 && new Set(matches.map((m) => m.state)).size > 1) {
      return { observerId, state: "CONFLICTING", observation: matches[0] };
    }
    return { observerId, state: matches[0].state, observation: matches[0] };
  });
}

export function decideEvidence(slots: EvidenceSlot[]): EvidenceFailure | "ok" {
  if (slots.some((s) => s.state === "FAILED")) return "EVIDENCE_FAILED";
  if (slots.some((s) => s.state !== "SATISFIED")) return "EVIDENCE_UNVERIFIABLE";
  if (slots.length === 0) return "EVIDENCE_UNVERIFIABLE";
  return "ok";
}

export function dropNonSatisfied(slots: EvidenceSlot[]): EvidenceSlot[] {
  return slots.filter((s) => s.state === "SATISFIED");
}
