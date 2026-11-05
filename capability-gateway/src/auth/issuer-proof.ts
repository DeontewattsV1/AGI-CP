import { createHmac, timingSafeEqual } from "node:crypto";
import type { Role } from "../capabilities/types.ts";

export type ProofRole = "ISSUER" | "ENFORCER";

export interface IssuerProof {
  requestId: string;
  subject: string;
  capability: string;
  signerRole: ProofRole | Role;
  signature: string;
}

export type IssuerProofFailure =
  | "ISSUER_PROOF_MISSING"
  | "ISSUER_PROOF_OBSERVER"
  | "ISSUER_PROOF_INVALID";

function canonical(proof: Omit<IssuerProof, "signature">): string {
  return [proof.requestId, proof.subject, proof.capability, proof.signerRole].join("|");
}

export function signIssuerProof(proof: Omit<IssuerProof, "signature">, key: string): string {
  return createHmac("sha256", key).update(canonical(proof)).digest("hex");
}

export function makeIssuerProof(
  fields: Omit<IssuerProof, "signature">,
  key: string,
): IssuerProof {
  return { ...fields, signature: signIssuerProof(fields, key) };
}

export function verifyIssuerProof(
  proof: IssuerProof | null | undefined,
  expected: { requestId: string; subject: string; capability: string; key: string | null | undefined },
): IssuerProofFailure | "ok" {
  if (!proof) return "ISSUER_PROOF_MISSING";
  if (proof.signerRole === "OBSERVER") return "ISSUER_PROOF_OBSERVER";
  if (proof.signerRole !== "ISSUER" && proof.signerRole !== "ENFORCER") {
    return "ISSUER_PROOF_OBSERVER";
  }
  if (
    proof.requestId !== expected.requestId ||
    proof.subject !== expected.subject ||
    proof.capability !== expected.capability
  ) {
    return "ISSUER_PROOF_INVALID";
  }
  if (!expected.key || !proof.signature) return "ISSUER_PROOF_INVALID";
  const expectedSig = signIssuerProof(proof, expected.key);
  if (expectedSig.length !== proof.signature.length) return "ISSUER_PROOF_INVALID";
  if (!timingSafeEqual(Buffer.from(expectedSig), Buffer.from(proof.signature))) {
    return "ISSUER_PROOF_INVALID";
  }
  return "ok";
}
