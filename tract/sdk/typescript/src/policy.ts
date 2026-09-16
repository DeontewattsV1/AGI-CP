export type Decision = "ALLOW" | "DENY" | "HOLD";
export type RiskClass = "NORMAL" | "OBSERVE" | "RESTRICT" | "QUARANTINE" | "TERMINATE";

export interface DelegationPolicy {
  allowed: boolean;
  maximum_depth: number;
  maximum_children: number;
}

export interface NetworkPolicy {
  default: "deny" | "allow";
  allow: string[];
}

export interface AgentPassport {
  tract_version: "0.1";
  subject: string;
  parent?: string | null;
  purpose: string;
  capabilities: string[];
  prohibited?: string[];
  resources: string[];
  delegation: DelegationPolicy;
  network: NetworkPolicy;
  issued_at: string;
  expires_at: string;
  nonce: string;
  issuer: string;
  signature: string;
}

const isSubset = (child: readonly string[], parent: readonly string[]): boolean => {
  const p = new Set(parent);
  return child.every((value) => p.has(value));
};

export function validateDelegation(parent: AgentPassport, child: AgentPassport): Decision {
  if (!parent.delegation.allowed) return "DENY";
  if (child.parent !== parent.subject) return "DENY";
  if (!isSubset(child.capabilities, parent.capabilities)) return "DENY";
  if (!isSubset(child.resources, parent.resources)) return "DENY";
  if (!isSubset(child.network.allow, parent.network.allow)) return "DENY";
  if (child.delegation.maximum_depth >= parent.delegation.maximum_depth) return "DENY";
  if (child.delegation.maximum_children > parent.delegation.maximum_children) return "DENY";
  return "ALLOW";
}

export function classifyRisk(score: number): RiskClass {
  if (!Number.isFinite(score) || score < 0 || score > 1) {
    throw new RangeError("risk score must be finite and between 0 and 1");
  }
  if (score < 0.25) return "NORMAL";
  if (score < 0.50) return "OBSERVE";
  if (score < 0.70) return "RESTRICT";
  if (score < 0.85) return "QUARANTINE";
  return "TERMINATE";
}

export function isExpired(passport: AgentPassport, now = new Date()): boolean {
  const expiry = Date.parse(passport.expires_at);
  return !Number.isFinite(expiry) || now.getTime() >= expiry;
}
