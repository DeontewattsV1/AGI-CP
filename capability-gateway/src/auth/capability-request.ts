import { createHmac, timingSafeEqual } from "node:crypto";

export interface CapabilityRequest {
  message_type: "CAPABILITY_REQUEST";
  protocol_version: "0.2.0";
  request_id: string;
  subject: string;
  capability: string;
  scope?: string;
  timestamp: number;
  nonce: string;
  signer_role: "AGENT";
  signature: string;
}

export type CapabilityRequestFailure =
  | "CAPABILITY_REQUEST_MISSING"
  | "CAPABILITY_REQUEST_UNSIGNED"
  | "CAPABILITY_REQUEST_SUBJECT_MISMATCH"
  | "CAPABILITY_REQUEST_OBSERVER_SIGNED"
  | "CAPABILITY_REQUEST_INVALID_SIGNATURE"
  | "CAPABILITY_REQUEST_CAPABILITY_MISMATCH";

function canonical(request: Omit<CapabilityRequest, "signature">): string {
  return [
    request.message_type,
    request.protocol_version,
    request.request_id,
    request.subject,
    request.capability,
    request.scope ?? "",
    String(request.timestamp),
    request.nonce,
    request.signer_role,
  ].join("|");
}

export function signCapabilityRequest(
  request: Omit<CapabilityRequest, "signature">,
  agentSecret: string,
): string {
  return createHmac("sha256", agentSecret).update(canonical(request)).digest("hex");
}

export function makeCapabilityRequest(
  fields: Omit<CapabilityRequest, "message_type" | "protocol_version" | "signature">,
  agentSecret: string,
): CapabilityRequest {
  const unsigned: Omit<CapabilityRequest, "signature"> = {
    message_type: "CAPABILITY_REQUEST",
    protocol_version: "0.2.0",
    ...fields,
  };
  return { ...unsigned, signature: signCapabilityRequest(unsigned, agentSecret) };
}

export function verifyCapabilityRequest(
  request: CapabilityRequest | null | undefined,
  expected: { subject: string; capability: string; agentSecret: string | null | undefined },
): CapabilityRequestFailure | "ok" {
  if (!request) return "CAPABILITY_REQUEST_MISSING";
  if (request.message_type !== "CAPABILITY_REQUEST") return "CAPABILITY_REQUEST_MISSING";
  if (!request.signature) return "CAPABILITY_REQUEST_UNSIGNED";
  if (request.signer_role !== "AGENT") return "CAPABILITY_REQUEST_OBSERVER_SIGNED";
  if (request.subject !== expected.subject) return "CAPABILITY_REQUEST_SUBJECT_MISMATCH";
  if (request.capability !== expected.capability) return "CAPABILITY_REQUEST_CAPABILITY_MISMATCH";
  if (!expected.agentSecret) return "CAPABILITY_REQUEST_INVALID_SIGNATURE";
  const expectedSig = signCapabilityRequest(request, expected.agentSecret);
  const given = request.signature;
  if (expectedSig.length !== given.length) return "CAPABILITY_REQUEST_INVALID_SIGNATURE";
  if (!timingSafeEqual(Buffer.from(expectedSig), Buffer.from(given))) {
    return "CAPABILITY_REQUEST_INVALID_SIGNATURE";
  }
  return "ok";
}
