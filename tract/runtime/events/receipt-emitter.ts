import { createHash, createPrivateKey, sign } from "node:crypto";
import { RuntimeEventBus } from "./event-bus.ts";

export interface ReceiptDraft {
  event_id: string;
  trace_id: string;
  agent_id: string;
  parent_agent_id?: string | null;
  action: { type: string; resource: string; arguments_digest: string };
  authorization: { capability: string; decision: "ALLOW" | "DENY" | "HOLD"; policy: string };
  risk: { score: number; classification: "NORMAL" | "OBSERVE" | "RESTRICT" | "QUARANTINE" | "TERMINATE" };
  timestamp: string;
}

export interface ReceiptInput extends ReceiptDraft {
  previous_event_hash: string;
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

export function unsignedReceipt(receipt: SignedReceipt): ReceiptInput {
  const { event_hash: _eventHash, signature: _signature, ...input } = receipt;
  return input;
}

export function verifyReceiptHash(receipt: SignedReceipt): boolean {
  return receiptHash(unsignedReceipt(receipt)) === receipt.event_hash;
}

export class ReceiptEmitter {
  private lastEventHash: string;
  private readonly privateKey: ReturnType<typeof createPrivateKey>;

  constructor(
    privateKeyPem: string,
    private readonly bus: RuntimeEventBus,
    genesisHash = `sha256:${"0".repeat(64)}`,
  ) {
    this.privateKey = createPrivateKey(privateKeyPem);
    if (this.privateKey.asymmetricKeyType !== "ed25519") throw new Error("receipt signing key must be Ed25519");
    this.lastEventHash = genesisHash;
  }

  tip(): string {
    return this.lastEventHash;
  }

  emit(draft: ReceiptDraft): SignedReceipt {
    const input: ReceiptInput = { ...draft, previous_event_hash: this.lastEventHash };
    const event_hash = receiptHash(input);
    const signature = sign(null, Buffer.from(event_hash, "utf8"), this.privateKey).toString("base64url");
    const receipt = Object.freeze({ ...input, event_hash, signature });
    this.lastEventHash = event_hash;
    this.bus.publish({
      event_id: receipt.event_id,
      trace_id: receipt.trace_id,
      agent_id: receipt.agent_id,
      parent_agent_id: receipt.parent_agent_id,
      capability: receipt.authorization.capability,
      decision: receipt.authorization.decision,
      risk: receipt.risk.score,
      previous_event_hash: receipt.previous_event_hash,
      event_hash,
      timestamp: receipt.timestamp,
    });
    return receipt;
  }
}
