import type { Capability, CapabilityDecision, Role } from "../capabilities/types.ts";

export interface PolicySnapshot {
  policyVersion: string;
  evaluatedAt: number;
  predicates: Record<string, boolean>;
  source: "ISSUER_EVALUATION" | "COPIED_ADJUDICATION" | "AGENT_SUPPLIED";
}

export interface ImportedAdjudication {
  decision: CapabilityDecision;
  signerRole?: Role;
}

export type IssuerPolicyFailure =
  | "POLICY_NOT_REEVALUATED"
  | "ISSUER_SIGNATURE_ORACLE"
  | "POLICY_DENIED"
  | "POLICY_VERSION_MISMATCH";

export const CURRENT_POLICY_VERSION = "v0.2.0";

export function evaluateIssuerPolicy(input: {
  capability: Capability;
  requestedScope?: string;
  now: number;
  snapshot: PolicySnapshot | null | undefined;
  importedAdjudication?: ImportedAdjudication | null;
  expectedPolicyVersion?: string;
}): IssuerPolicyFailure | "ok" {
  const expected = input.expectedPolicyVersion ?? CURRENT_POLICY_VERSION;

  if (input.importedAdjudication && input.importedAdjudication.decision === "ALLOW") {
    if (!input.snapshot || input.snapshot.source !== "ISSUER_EVALUATION") {
      return "ISSUER_SIGNATURE_ORACLE";
    }
  }

  if (!input.snapshot) return "POLICY_NOT_REEVALUATED";
  if (input.snapshot.source !== "ISSUER_EVALUATION") return "ISSUER_SIGNATURE_ORACLE";
  if (input.snapshot.policyVersion !== expected) return "POLICY_VERSION_MISMATCH";
  if (!Number.isFinite(input.snapshot.evaluatedAt)) return "POLICY_NOT_REEVALUATED";
  if (Math.abs(input.now - input.snapshot.evaluatedAt) > 5 * 60 * 1000) {
    return "POLICY_NOT_REEVALUATED";
  }

  const required = ["scope_allowed", "risk_allowed", "fresh"];
  for (const key of required) {
    if (input.snapshot.predicates[key] !== true) return "POLICY_DENIED";
  }

  if (input.requestedScope && input.snapshot.predicates.scope_allowed !== true) {
    return "POLICY_DENIED";
  }

  return "ok";
}

export function issuerEvaluation(
  now: number,
  over: Partial<PolicySnapshot["predicates"]> = {},
): PolicySnapshot {
  return {
    policyVersion: CURRENT_POLICY_VERSION,
    evaluatedAt: now,
    source: "ISSUER_EVALUATION",
    predicates: {
      scope_allowed: true,
      risk_allowed: true,
      fresh: true,
      ...over,
    },
  };
}
