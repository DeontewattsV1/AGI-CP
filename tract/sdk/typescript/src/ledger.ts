import { createHash } from "node:crypto";
import type { Decision, RiskClass } from "./policy.js";

export interface EventReceiptInput {
  event_id: string;
  trace_id: string;
  agent_id: string;
  parent_agent_id?: string | null;
  action: {
    type: string;
    resource: string;
    arguments_digest: string;
  };
  authorization: {
    capability: string;
    decision: Decision;
    policy: string;
  };
  risk: {
    score: number;
    classification: RiskClass;
  };
  previous_event_hash: string;
  timestamp: string;
}

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
}

export function computeEventHash(input: EventReceiptInput): string {
  const digest = createHash("sha256").update(canonicalize(input)).digest("hex");
  return `sha256:${digest}`;
}

export function verifyEventHash(input: EventReceiptInput, eventHash: string): boolean {
  return computeEventHash(input) === eventHash;
}

export function verifyChain(
  receipts: ReadonlyArray<EventReceiptInput & { event_hash: string }>,
  genesisHash: string,
): boolean {
  let previous = genesisHash;
  for (const receipt of receipts) {
    if (receipt.previous_event_hash !== previous) return false;
    const { event_hash, ...input } = receipt;
    if (!verifyEventHash(input, event_hash)) return false;
    previous = event_hash;
  }
  return true;
}
