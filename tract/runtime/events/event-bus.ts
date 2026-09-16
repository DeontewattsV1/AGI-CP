export interface RuntimeEvent {
  event_id: string;
  trace_id: string;
  agent_id: string;
  parent_agent_id?: string | null;
  capability: string;
  decision: "ALLOW" | "DENY" | "HOLD";
  risk: number;
  event_hash: string;
  timestamp: string;
}

export type RuntimeEventListener = (event: Readonly<RuntimeEvent>) => void;

/**
 * Write access is intentionally held by the runtime emitter only.
 * Consumers receive a ReadOnlyEventStream and cannot publish authority state.
 */
export interface ReadOnlyEventStream {
  subscribe(listener: RuntimeEventListener): () => void;
  snapshot(): readonly Readonly<RuntimeEvent>[];
}

export class RuntimeEventBus {
  private readonly listeners = new Set<RuntimeEventListener>();
  private readonly events: RuntimeEvent[] = [];

  readonly stream: ReadOnlyEventStream = {
    subscribe: (listener) => {
      this.listeners.add(listener);
      return () => this.listeners.delete(listener);
    },
    snapshot: () => this.events.map((event) => Object.freeze({ ...event })),
  };

  publish(event: RuntimeEvent): void {
    const frozen = Object.freeze({ ...event });
    this.events.push(frozen);
    for (const listener of this.listeners) listener(frozen);
  }
}
