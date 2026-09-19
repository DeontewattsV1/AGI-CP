import { createHash } from "node:crypto";
import type { Decision, RiskClass } from "./policy.js";

export interface EventReceiptInput {
  event_id: string;
  trace_id: string;
  agent_id: string;
  parent_agent_id?: string | null;
  action: { type: string; resource: string; arguments_digest: string };
  authorization: { capability: string; decision: Decision; policy: string };
  risk: { score: number; classification: RiskClass };
  previous_event_hash: string;
  timestamp: string;
}

export interface EventReceipt extends EventReceiptInput {
  event_hash: string;
  signature?: string;
}

export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().filter((key) => record[key] !== undefined).map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
}

export function computeEventHash(input: EventReceiptInput): string {
  const digest = createHash("sha256").update(canonicalize(input)).digest("hex");
  return `sha256:${digest}`;
}

export function verifyEventHash(input: EventReceiptInput, eventHash: string): boolean {
  return computeEventHash(input) === eventHash;
}

export function unsignedProjection(receipt: EventReceipt): EventReceiptInput {
  const { event_hash: _eventHash, signature: _signature, ...input } = receipt;
  return input;
}

export function verifyChain(receipts: ReadonlyArray<EventReceipt>, genesisHash: string): boolean {
  let previous = genesisHash;
  for (const receipt of receipts) {
    if (receipt.previous_event_hash !== previous) return false;
    if (!verifyEventHash(unsignedProjection(receipt), receipt.event_hash)) return false;
    previous = receipt.event_hash;
  }
  return true;
}
