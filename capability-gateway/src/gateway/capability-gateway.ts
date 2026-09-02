import { hasIdentity } from "../auth/identity.ts";
import { verifySignature } from "../auth/signature.ts";
import { scopePermits, validateDelegation } from "../auth/delegation.ts";
import type { ReplayStore } from "../auth/replay.ts";
import type { RevocationStore } from "../auth/revocation.ts";
import type {
  Capability,
  CapabilityDecision,
  Delegation,
  DeploymentAttestation,
  DenyReason,
  Role,
  SignedRequestEnvelope,
  VerificationResult,
} from "../capabilities/types.ts";

export interface VerificationContext {
  envelope: SignedRequestEnvelope;
  resolvedKey?: string | null;
  issuerRole?: Role;
  delegation?: Delegation | null;
  capability?: Capability | null;
  requestedScope?: string;
  now?: number;
  maxSkewMs?: number;
  deploymentAttestation?: DeploymentAttestation | null;
  extraVerifier?: () => CapabilityDecision;
}

export interface GatewayDeps {
  replayStore: ReplayStore | null;
  revocationStore: RevocationStore | null;
}

const DEFAULT_SKEW_MS = 5 * 60 * 1000;

function deny(reason: DenyReason, envelope: SignedRequestEnvelope, capabilityId?: string): VerificationResult {
  return {
    decision: "DENY",
    reason,
    requestId: envelope.requestId,
    capabilityId,
  };
}

export async function authorizeCapability(
  ctx: VerificationContext,
  deps: GatewayDeps,
): Promise<VerificationResult> {
  const envelope = ctx.envelope;
  const capability = ctx.capability ?? null;
  const now = ctx.now ?? Date.now();
  const skew = ctx.maxSkewMs ?? DEFAULT_SKEW_MS;

  if (!hasIdentity(envelope)) {
    return deny("IDENTITY_MISSING", envelope, capability?.id);
  }
  if (!capability) {
    return deny("UNKNOWN_CAPABILITY", envelope);
  }
  if (!envelope.capability || envelope.capability !== capability.id) {
    return deny("AUTHORIZATION_MISSING", envelope, capability.id);
  }
  if (capability.requiresSignature) {
    if (!ctx.resolvedKey) {
      return deny("KEY_NOT_RESOLVED", envelope, capability.id);
    }
    if (ctx.issuerRole === "OBSERVER") {
      return deny("OBSERVER_KEY_USED_AS_ISSUER", envelope, capability.id);
    }
    if (!verifySignature(envelope, ctx.resolvedKey)) {
      return deny("INVALID_SIGNATURE", envelope, capability.id);
    }
  }
  if (Math.abs(now - envelope.timestamp) > skew) {
    return deny("TIMESTAMP_OUTSIDE_WINDOW", envelope, capability.id);
  }
  if (capability.requiresRevocationCheck) {
    if (!deps.revocationStore) {
      return deny("REVOCATION_CONTROL_MISSING", envelope, capability.id);
    }
    const ids = [envelope.requestId, envelope.delegationId, envelope.issuer, envelope.subject].filter(Boolean);
    for (const id of ids) {
      if (await deps.revocationStore.isRevoked(id)) {
        return deny("REVOKED", envelope, capability.id);
      }
    }
  }
  if (capability.requiresReplayProtection) {
    if (!deps.replayStore) {
      return deny("REPLAY_CONTROL_MISSING", envelope, capability.id);
    }
    if (await deps.replayStore.seen(envelope.requestId, envelope.nonce)) {
      return deny("REPLAY_DETECTED", envelope, capability.id);
    }
    await deps.replayStore.remember(envelope.requestId, envelope.nonce);
  }
  const d = validateDelegation(ctx.delegation, envelope, capability, ctx.requestedScope);
  if (d !== "ok") {
    return deny(d, envelope, capability.id);
  }
  if (ctx.requestedScope && !scopePermits(capability.scopes, ctx.requestedScope)) {
    if (!ctx.delegation || !scopePermits(ctx.delegation.scopes, ctx.requestedScope)) {
      return deny("SCOPE_MISMATCH", envelope, capability.id);
    }
  }
  if (capability.risk === "SECURITY_CRITICAL" || capability.requiresDeploymentControl) {
    const att = ctx.deploymentAttestation;
    if (!att) {
      return deny(
        capability.risk === "SECURITY_CRITICAL" ? "DEPLOYMENT_ATTESTATION_MISSING" : "DEPLOYMENT_CONTROL_REQUIRED",
        envelope,
        capability.id,
      );
    }
    if (!att.approved) {
      return deny("DEPLOYMENT_NOT_APPROVED", envelope, capability.id);
    }
    if (att.expiresAt !== undefined && now > att.expiresAt) {
      return deny("DEPLOYMENT_ATTESTATION_EXPIRED", envelope, capability.id);
    }
  }
  if (ctx.extraVerifier) {
    const extra = ctx.extraVerifier();
    if (extra === "DENY") {
      return deny("EXTERNAL_DENY", envelope, capability.id);
    }
    if (extra === "INDETERMINATE") {
      return {
        decision: "INDETERMINATE",
        reason: "INDETERMINATE",
        requestId: envelope.requestId,
        capabilityId: capability.id,
      };
    }
  }
  return {
    decision: "ALLOW",
    reason: "ALLOW",
    requestId: envelope.requestId,
    capabilityId: capability.id,
  };
}
