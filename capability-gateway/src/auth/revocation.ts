export type RevocationReason =
  | "POLICY_FAILURE"
  | "EVIDENCE_STALE"
  | "OBSERVER_FAILURE"
  | "GATEWAY_FAILURE"
  | "TOKEN_EXPIRY"
  | "IDENTITY_REVOCATION"
  | "EMERGENCY_STOP"
  | "SCOPE_INVALIDATION"
  | "PARENT_REVOKED";

export interface RevocationMessage {
  protocol_version: "0.2.0";
  message_type: "REVOCATION";
  revocation_id: string;
  target_id: string;
  parent_id?: string;
  reason: RevocationReason;
  issued_at: number;
  issuer_id: string;
  issuer_role: "ISSUER" | "ENFORCER" | "HUMAN_AUTHORITY" | "RECORDER";
}

export interface RevocationStore {
  isRevoked(id: string, at?: number): Promise<boolean>;
  apply?(message: RevocationMessage): Promise<void>;
}

export const DEFAULT_ACCEPTANCE_WINDOW_MS = 5_000;

export class MemoryRevocationStore implements RevocationStore {
  private readonly records = new Map<string, RevocationMessage>();
  private readonly children = new Map<string, Set<string>>();
  readonly acceptanceWindowMs: number;

  constructor(acceptanceWindowMs = DEFAULT_ACCEPTANCE_WINDOW_MS) {
    this.acceptanceWindowMs = acceptanceWindowMs;
  }

  registerLineage(id: string, parentId?: string): void {
    if (!parentId) return;
    const set = this.children.get(parentId) ?? new Set<string>();
    set.add(id);
    this.children.set(parentId, set);
  }

  async apply(message: RevocationMessage): Promise<void> {
    if (message.message_type !== "REVOCATION") return;
    this.revokeTree(message.target_id, message);
  }

  revoke(id: string): void {
    const now = Date.now();
    void this.apply({
      protocol_version: "0.2.0",
      message_type: "REVOCATION",
      revocation_id: `legacy-${id}-${now}`,
      target_id: id,
      reason: "IDENTITY_REVOCATION",
      issued_at: now,
      issuer_id: "legacy",
      issuer_role: "ENFORCER",
    });
  }

  async isRevoked(id: string, at = Date.now()): Promise<boolean> {
    const record = this.records.get(id);
    if (!record) return false;
    return at >= record.issued_at;
  }

  acceptanceDeadline(id: string): number | undefined {
    const record = this.records.get(id);
    if (!record) return undefined;
    return record.issued_at + this.acceptanceWindowMs;
  }

  private revokeTree(id: string, source: RevocationMessage): void {
    if (this.records.has(id)) return;
    this.records.set(id, {
      ...source,
      target_id: id,
      reason: id === source.target_id ? source.reason : "PARENT_REVOKED",
    });
    for (const child of this.children.get(id) ?? []) {
      this.revokeTree(child, source);
    }
  }
}

export function revocationMessage(
  partial: Omit<RevocationMessage, "protocol_version" | "message_type">,
): RevocationMessage {
  return {
    protocol_version: "0.2.0",
    message_type: "REVOCATION",
    ...partial,
  };
}
