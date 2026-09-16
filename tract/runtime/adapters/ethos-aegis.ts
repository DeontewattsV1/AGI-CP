export interface AegisSignal {
  source: "ethos-aegis";
  verdict: "SANCTIFIED" | "OBSERVE" | "RESTRICT" | "QUARANTINE" | "BLOCK" | "UNVERIFIABLE";
  threatClasses: string[];
  taintScore: number;
  confidence?: number;
  evidenceDigests: string[];
}

export interface TractBehaviorSignal {
  source: "ethos-aegis";
  risk: number;
  closed: boolean;
  reasons: string[];
  evidenceDigests: string[];
}

/**
 * Converts Aegis observations into TRACT evidence. It cannot mint capability.
 */
export function adaptAegisSignal(signal: AegisSignal): TractBehaviorSignal {
  const taint = Math.min(1, Math.max(0, signal.taintScore));
  const floor: Record<AegisSignal["verdict"], number> = {
    SANCTIFIED: 0,
    OBSERVE: 0.25,
    RESTRICT: 0.50,
    QUARANTINE: 0.70,
    BLOCK: 0.85,
    UNVERIFIABLE: 1,
  };
  const risk = Math.max(taint, floor[signal.verdict]);
  return {
    source: "ethos-aegis",
    risk,
    closed: signal.verdict === "BLOCK" || signal.verdict === "UNVERIFIABLE",
    reasons: [signal.verdict, ...signal.threatClasses],
    evidenceDigests: signal.evidenceDigests,
  };
}
