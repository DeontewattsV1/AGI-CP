export interface RuntimeEvent {
  event_id: string;
  trace_id: string;
  agent_id: string;
  parent_agent_id?: string | null;
  capability: string;
  decision: "ALLOW" | "DENY" | "HOLD";
  risk: number;
  previous_event_hash: string;
  event_hash: string;
  timestamp: string;
}

export type RuntimeEventListener = (event: Readonly<RuntimeEvent>) => void;
export type ListenerErrorHandler = (error: unknown) => void;

/**
 * Write access is intentionally held by the trusted runtime emitter only.
 * Consumers receive a ReadOnlyEventStream and cannot publish authority state.
 */
export interface ReadOnlyEventStream {
  subscribe(listener: RuntimeEventListener): () => void;
  snapshot(): readonly Readonly<RuntimeEvent>[];
}

export class RuntimeEventBus {
  private readonly listeners = new Set<RuntimeEventListener>();
  private readonly events: Readonly<RuntimeEvent>[] = [];

  constructor(
    private readonly maxEvents = 2048,
    private readonly onListenerError: ListenerErrorHandler = () => {},
  ) {
    if (!Number.isInteger(maxEvents) || maxEvents < 1) throw new Error("maxEvents must be a positive integer");
  }

  readonly stream: ReadOnlyEventStream = {
    subscribe: (listener) => {
      this.listeners.add(listener);
      return () => this.listeners.delete(listener);
    },
    snapshot: () => this.events.slice(),
  };

  publish(event: RuntimeEvent): void {
    const frozen = Object.freeze({ ...event });
    this.events.push(frozen);
    if (this.events.length > this.maxEvents) this.events.splice(0, this.events.length - this.maxEvents);
    for (const listener of this.listeners) {
      try {
        listener(frozen);
      } catch (error) {
        this.onListenerError(error);
      }
    }
  }
}
