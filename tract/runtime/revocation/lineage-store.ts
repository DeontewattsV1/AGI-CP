export interface RevocationRecord {
  principalId: string;
  reason: string;
  revokedAt: string;
  sourceEventId?: string;
}

/** Reference in-memory implementation. Production deployments need durable storage. */
export class LineageRevocationStore {
  private readonly parent = new Map<string, string>();
  private readonly children = new Map<string, Set<string>>();
  private readonly revoked = new Map<string, RevocationRecord>();

  register(principalId: string, parentId?: string): void {
    if (!parentId) return;
    this.parent.set(principalId, parentId);
    const descendants = this.children.get(parentId) ?? new Set<string>();
    descendants.add(principalId);
    this.children.set(parentId, descendants);
  }

  revoke(principalId: string, reason: string, revokedAt = new Date().toISOString(), sourceEventId?: string): RevocationRecord[] {
    const affected = [principalId, ...this.descendantsOf(principalId)];
    return affected.map((id) => {
      const record = { principalId: id, reason, revokedAt, sourceEventId };
      this.revoked.set(id, record);
      return record;
    });
  }

  isRevoked(principalId: string): boolean {
    if (this.revoked.has(principalId)) return true;
    let cursor = this.parent.get(principalId);
    const seen = new Set<string>();
    while (cursor && !seen.has(cursor)) {
      seen.add(cursor);
      if (this.revoked.has(cursor)) return true;
      cursor = this.parent.get(cursor);
    }
    return false;
  }

  descendantsOf(principalId: string): string[] {
    const result: string[] = [];
    const queue = [...(this.children.get(principalId) ?? [])];
    const seen = new Set<string>();
    while (queue.length) {
      const current = queue.shift()!;
      if (seen.has(current)) continue;
      seen.add(current);
      result.push(current);
      queue.push(...(this.children.get(current) ?? []));
    }
    return result;
  }
}
