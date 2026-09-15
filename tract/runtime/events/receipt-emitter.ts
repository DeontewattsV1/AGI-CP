import { createHash, sign } from "node:crypto";
import { RuntimeEventBus } from "./event-bus.ts";

export interface ReceiptInput {
  event_id: string;
  trace_id: string;
  agent_id: string;
  parent_agent_id?: string | null;
  action: { type: string; resource: string; arguments_digest: string };
  authorization: { capability: string; decision: "ALLOW" | "DENY" | "HOLD"; policy: string };
  risk: { score: number; classification: "NORMAL" | "OBSERVE" | "RESTRICT" | "QUARANTINE" | "TERMINATE" };
  previous_event_hash: string;
  timestamp: string;
}

export interface SignedReceipt extends ReceiptInput {
  event_hash: string;
  signature: string;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().filter((key) => object[key] !== undefined).map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
}

export function receiptHash(input: ReceiptInput): string {
  return `sha256:${createHash("sha256").update(canonical(input)).digest("hex")}`;
}

export class ReceiptEmitter {
  constructor(private readonly privateKeyPem: string, private readonly bus: RuntimeEventBus) {}

  emit(input: ReceiptInput): SignedReceipt {
    const event_hash = receiptHash(input);
    const signature = sign(null, Buffer.from(event_hash, "utf8"), this.privateKeyPem).toString("base64url");
    const receipt = Object.freeze({ ...input, event_hash, signature });
    this.bus.publish({
      event_id: receipt.event_id,
      trace_id: receipt.trace_id,
      agent_id: receipt.agent_id,
      parent_agent_id: receipt.parent_agent_id,
      capability: receipt.authorization.capability,
      decision: receipt.authorization.decision,
      risk: receipt.risk.score,
      event_hash,
      timestamp: receipt.timestamp,
    });
    return receipt;
  }
}
