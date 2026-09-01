import type { Capability, Delegation } from "../capabilities/types.ts";

export function validateDelegation(
  delegation: Delegation | null | undefined,
  envelope: { issuer: string; subject: string; capability: string; timestamp: number },
  capability: Capability,
  requestedScope?: string,
): "ok" | "DELEGATION_NOT_FOUND" | "INVALID_DELEGATION" | "SCOPE_MISMATCH" {
  if (!capability.requiresDelegation) return "ok";
  if (!delegation) return "DELEGATION_NOT_FOUND";
  if (delegation.revoked) return "INVALID_DELEGATION";
  if (envelope.timestamp < delegation.issuedAt || envelope.timestamp > delegation.expiresAt) {
    return "INVALID_DELEGATION";
  }
  if (delegation.issuer !== envelope.issuer || delegation.subject !== envelope.subject) {
    return "INVALID_DELEGATION";
  }
  if (!delegation.capabilities.includes(envelope.capability)) {
    return "INVALID_DELEGATION";
  }
  if (requestedScope && !scopePermits(delegation.scopes, requestedScope) && !scopePermits(capability.scopes, requestedScope)) {
    return "SCOPE_MISMATCH";
  }
  return "ok";
}

export function scopePermits(authorized: string[], requested: string): boolean {
  return authorized.some((scope) => {
    if (scope === requested) return true;
    if (scope.endsWith(":*")) {
      const prefix = scope.slice(0, -1);
      return requested.startsWith(prefix);
    }
    return false;
  });
}
