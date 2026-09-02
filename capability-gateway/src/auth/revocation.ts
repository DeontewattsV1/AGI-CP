export interface RevocationStore {
  isRevoked(id: string): Promise<boolean>;
}

export class MemoryRevocationStore implements RevocationStore {
  private readonly revoked = new Set<string>();

  revoke(id: string): void {
    this.revoked.add(id);
  }

  async isRevoked(id: string): Promise<boolean> {
    return this.revoked.has(id);
  }
}
