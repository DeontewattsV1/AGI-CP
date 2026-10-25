import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { authorizeCapability } from "../src/gateway/capability-gateway.ts";
import { signEnvelope } from "../src/auth/signature.ts";
import { makeCapabilityRequest } from "../src/auth/capability-request.ts";
import { issuerEvaluation } from "../src/auth/issuer-policy.ts";
import { MemoryReplayStore } from "../src/auth/replay.ts";
import { MemoryRevocationStore } from "../src/auth/revocation.ts";
import { getCapability } from "../src/capabilities/registry.ts";
import type { Delegation, SignedRequestEnvelope } from "../src/capabilities/types.ts";

const ISSUER = "test-issuer-secret";
const AGENT = "test-agent-secret";
const now = Date.now();

function envelope(): SignedRequestEnvelope {
  const base = {
    requestId: "req-pol-1",
    timestamp: now,
    issuer: "issuer-1",
    subject: "agent-A17",
    capability: "agicp.tool.bounded",
    delegationId: "dlg-1",
    nonce: "nonce-pol-1",
    payload: {},
    signature: "",
  };
  return { ...base, signature: signEnvelope(base, ISSUER) };
}

function delegation(): Delegation {
  return {
    id: "dlg-1",
    issuer: "issuer-1",
    subject: "agent-A17",
    capabilities: ["agicp.tool.bounded"],
    scopes: ["tool:bounded:*"],
    issuedAt: now - 1000,
    expiresAt: now + 60_000,
    revoked: false,
  };
}

function request() {
  return makeCapabilityRequest({
    request_id: "req-pol-1",
    subject: "agent-A17",
    capability: "agicp.tool.bounded",
    timestamp: now,
    nonce: "req-nonce",
    signer_role: "AGENT",
  }, AGENT);
}

function deps() {
  return { replayStore: new MemoryReplayStore(), revocationStore: new MemoryRevocationStore() };
}

function baseCtx() {
  return {
    envelope: envelope(),
    resolvedKey: ISSUER,
    issuerRole: "ISSUER" as const,
    agentKey: AGENT,
    capabilityRequest: request(),
    delegation: delegation(),
    capability: getCapability("agicp.tool.bounded")!,
    requestedScope: "tool:bounded:write",
    now,
  };
}

describe("issuer policy re-evaluation", () => {
  it("ALLOW when issuer evaluates current policy", async () => {
    const result = await authorizeCapability({ ...baseCtx(), policySnapshot: issuerEvaluation(now) }, deps());
    assert.equal(result.decision, "ALLOW");
  });
  it("copied adjudication without issuer evaluation is an oracle", async () => {
    const result = await authorizeCapability({
      ...baseCtx(),
      policySnapshot: null,
      importedAdjudication: { decision: "ALLOW", signerRole: "JUDGE" },
    }, deps());
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "ISSUER_SIGNATURE_ORACLE");
  });
  it("missing snapshot => POLICY_NOT_REEVALUATED", async () => {
    const result = await authorizeCapability({ ...baseCtx(), policySnapshot: null }, deps());
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "POLICY_NOT_REEVALUATED");
  });
  it("failed predicate => POLICY_DENIED", async () => {
    const result = await authorizeCapability({
      ...baseCtx(),
      policySnapshot: issuerEvaluation(now, { scope_allowed: false }),
    }, deps());
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "POLICY_DENIED");
  });
});
