import type { Capability } from "./types.ts";

const catalog: Record<string, Capability> = {
  "agicp.observe": {
    id: "agicp.observe",
    version: "0.2.0",
    risk: "READ",
    description: "Submit an observation. Cannot mint capability.",
    scopes: ["observe:*"],
    requiresDeploymentControl: false,
    requiresDelegation: true,
    requiresSignature: true,
    requiresReplayProtection: true,
    requiresRevocationCheck: true,
  },
  "agicp.tool.bounded": {
    id: "agicp.tool.bounded",
    version: "0.2.0",
    risk: "WRITE",
    description: "C1/C2 bounded tool use.",
    scopes: ["tool:bounded:*"],
    requiresDeploymentControl: false,
    requiresDelegation: true,
    requiresSignature: true,
    requiresReplayProtection: true,
    requiresRevocationCheck: true,
  },
  "agicp.tool.high_consequence": {
    id: "agicp.tool.high_consequence",
    version: "0.2.0",
    risk: "DESTRUCTIVE",
    description: "C3 high-consequence capability.",
    scopes: ["tool:c3:*"],
    requiresDeploymentControl: false,
    requiresDelegation: true,
    requiresSignature: true,
    requiresReplayProtection: true,
    requiresRevocationCheck: true,
  },
  "agicp.containment.modify": {
    id: "agicp.containment.modify",
    version: "0.2.0",
    risk: "SECURITY_CRITICAL",
    description: "C4 modification of containment infrastructure. Not delegable to the agent.",
    scopes: ["containment:modify"],
    requiresDeploymentControl: true,
    requiresDelegation: true,
    requiresSignature: true,
    requiresReplayProtection: true,
    requiresRevocationCheck: true,
  },
};

export function getCapability(id: string): Capability | undefined {
  return catalog[id];
}

export function listCapabilities(): Capability[] {
  return Object.values(catalog);
}
