export type CapabilityRisk = "READ" | "WRITE" | "DESTRUCTIVE" | "SECURITY_CRITICAL";

export type CapabilityDecision = "ALLOW" | "DENY" | "INDETERMINATE";

export type DenyReason =
  | "IDENTITY_MISSING"
  | "KEY_NOT_RESOLVED"
  | "INVALID_SIGNATURE"
  | "TIMESTAMP_OUTSIDE_WINDOW"
  | "REVOCATION_CONTROL_MISSING"
  | "REVOKED"
  | "REPLAY_CONTROL_MISSING"
  | "REPLAY_DETECTED"
  | "DELEGATION_NOT_FOUND"
  | "INVALID_DELEGATION"
  | "SCOPE_MISMATCH"
  | "UNKNOWN_CAPABILITY"
  | "DEPLOYMENT_ATTESTATION_MISSING"
  | "DEPLOYMENT_NOT_APPROVED"
  | "DEPLOYMENT_ATTESTATION_EXPIRED"
  | "DEPLOYMENT_CONTROL_REQUIRED"
  | "AUTHORIZATION_MISSING"
  | "EXTERNAL_DENY"
  | "OBSERVER_KEY_USED_AS_ISSUER";

export interface Capability {
  id: string;
  version: string;
  risk: CapabilityRisk;
  description: string;
  scopes: string[];
  requiresDeploymentControl: boolean;
  requiresDelegation: boolean;
  requiresSignature: boolean;
  requiresReplayProtection: boolean;
  requiresRevocationCheck: boolean;
}

export interface DeploymentAttestation {
  approved: boolean;
  environment: "development" | "staging" | "production";
  approvedBy: string;
  approvedAt: number;
  attestationId: string;
  expiresAt?: number;
}

export interface SignedRequestEnvelope {
  requestId: string;
  timestamp: number;
  issuer: string;
  subject: string;
  capability: string;
  delegationId: string;
  nonce: string;
  payload: unknown;
  signature: string;
}

export interface Delegation {
  id: string;
  issuer: string;
  subject: string;
  capabilities: string[];
  scopes: string[];
  issuedAt: number;
  expiresAt: number;
  revoked: boolean;
  parentId?: string;
}

export interface VerificationResult {
  decision: CapabilityDecision;
  reason?: DenyReason | "INDETERMINATE" | "ALLOW";
  capabilityId?: string;
  requestId?: string;
}

export type Role = "AGENT" | "OBSERVER" | "JUDGE" | "ISSUER" | "ENFORCER" | "RECORDER" | "HUMAN_AUTHORITY";
