export interface ReplayStore {
  seen(requestId: string, nonce: string): Promise<boolean>;
  remember(requestId: string, nonce: string): Promise<void>;
}

export class MemoryReplayStore implements ReplayStore {
  private readonly seenKeys = new Set<string>();

  async seen(requestId: string, nonce: string): Promise<boolean> {
    return this.seenKeys.has(`${requestId}:${nonce}`);
  }

  async remember(requestId: string, nonce: string): Promise<void> {
    this.seenKeys.add(`${requestId}:${nonce}`);
  }
}
