import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { authorizeCapability } from "../src/gateway/capability-gateway.ts";
import { signEnvelope } from "../src/auth/signature.ts";
import { makeCapabilityRequest } from "../src/auth/capability-request.ts";
import { issuerEvaluation } from "../src/auth/issuer-policy.ts";
import { makeIssuerProof } from "../src/auth/issuer-proof.ts";
import { MemoryReplayStore } from "../src/auth/replay.ts";
import { MemoryRevocationStore } from "../src/auth/revocation.ts";
import { getCapability } from "../src/capabilities/registry.ts";
import type { Delegation, SignedRequestEnvelope } from "../src/capabilities/types.ts";

const ISSUER = "test-issuer-secret";
const AGENT = "test-agent-secret";
const now = Date.now();

function envelope(): SignedRequestEnvelope {
  const base = {
    requestId: "req-pr-1",
    timestamp: now,
    issuer: "issuer-1",
    subject: "agent-A17",
    capability: "agicp.tool.bounded",
    delegationId: "dlg-1",
    nonce: "nonce-pr-1",
    payload: {},
    signature: "",
  };
  return { ...base, signature: signEnvelope(base, ISSUER) };
}

function ctx() {
  const env = envelope();
  return {
    envelope: env,
    resolvedKey: ISSUER,
    issuerRole: "ISSUER" as const,
    agentKey: AGENT,
    policySnapshot: issuerEvaluation(now),
    capabilityRequest: makeCapabilityRequest({
      request_id: env.requestId,
      subject: env.subject,
      capability: env.capability,
      timestamp: now,
      nonce: "req-nonce",
      signer_role: "AGENT",
    }, AGENT),
    delegation: {
      id: "dlg-1",
      issuer: "issuer-1",
      subject: "agent-A17",
      capabilities: ["agicp.tool.bounded"],
      scopes: ["tool:bounded:*"],
      issuedAt: now - 1000,
      expiresAt: now + 60_000,
      revoked: false,
    } satisfies Delegation,
    capability: getCapability("agicp.tool.bounded")!,
    requestedScope: "tool:bounded:write",
    now,
  };
}

function deps() {
  return { replayStore: new MemoryReplayStore(), revocationStore: new MemoryRevocationStore() };
}

describe("issuer_proof", () => {
  it("ALLOW when K_U signs authorization fields", async () => {
    const env = envelope();
    const result = await authorizeCapability({
      ...ctx(),
      issuerProof: makeIssuerProof({
        requestId: env.requestId,
        subject: env.subject,
        capability: env.capability,
        signerRole: "ISSUER",
      }, ISSUER),
      issuerProofKey: ISSUER,
    }, deps());
    assert.equal(result.decision, "ALLOW");
  });
  it("observer-signed proof is rejected", async () => {
    const env = envelope();
    const result = await authorizeCapability({
      ...ctx(),
      issuerProof: {
        requestId: env.requestId,
        subject: env.subject,
        capability: env.capability,
        signerRole: "OBSERVER",
        signature: "00",
      },
      issuerProofKey: ISSUER,
    }, deps());
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "ISSUER_PROOF_OBSERVER");
  });
  it("missing proof is rejected", async () => {
    const result = await authorizeCapability({
      ...ctx(),
      issuerProof: null,
      issuerProofKey: ISSUER,
    }, deps());
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "ISSUER_PROOF_MISSING");
  });
});
