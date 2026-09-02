import { createHmac, timingSafeEqual } from "node:crypto";
import type { SignedRequestEnvelope } from "../capabilities/types.ts";

export function canonicalMessage(envelope: SignedRequestEnvelope): string {
  return [
    envelope.requestId,
    String(envelope.timestamp),
    envelope.issuer,
    envelope.subject,
    envelope.capability,
    envelope.delegationId,
    envelope.nonce,
  ].join("|");
}

export function signEnvelope(envelope: Omit<SignedRequestEnvelope, "signature">, secret: string): string {
  const message = canonicalMessage({ ...envelope, signature: "" });
  return createHmac("sha256", secret).update(message).digest("hex");
}

export function verifySignature(envelope: SignedRequestEnvelope, secret: string | null | undefined): boolean {
  if (!secret) return false;
  const expected = signEnvelope(envelope, secret);
  const given = envelope.signature ?? "";
  if (expected.length !== given.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(given));
}
