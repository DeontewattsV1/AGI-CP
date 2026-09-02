import type { SignedRequestEnvelope } from "../capabilities/types.ts";

export function hasIdentity(envelope: SignedRequestEnvelope): boolean {
  return Boolean(envelope.issuer?.trim() && envelope.subject?.trim());
}
