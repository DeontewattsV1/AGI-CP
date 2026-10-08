import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { authorizeCapability } from "../src/gateway/capability-gateway.ts";
import { issuerEvaluation } from "../src/auth/issuer-policy.ts";
import { signEnvelope } from "../src/auth/signature.ts";
import { makeCapabilityRequest } from "../src/auth/capability-request.ts";
import { MemoryReplayStore } from "../src/auth/replay.ts";
import { MemoryRevocationStore } from "../src/auth/revocation.ts";
import { getCapability } from "../src/capabilities/registry.ts";
import type { Delegation, SignedRequestEnvelope } from "../src/capabilities/types.ts";

const ISSUER = "test-issuer-secret";
const AGENT = "test-agent-secret";
const now = Date.now();

function envelope(): SignedRequestEnvelope {
  const base = {
    requestId: "req-cr-1",
    timestamp: now,
    issuer: "issuer-1",
    subject: "agent-A17",
    capability: "agicp.tool.bounded",
    delegationId: "dlg-1",
    nonce: "nonce-cr-1",
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

function request(over: Record<string, string> = {}) {
  return makeCapabilityRequest(
    {
      request_id: "req-cr-1",
      subject: over.subject ?? "agent-A17",
      capability: over.capability ?? "agicp.tool.bounded",
      scope: "tool:bounded:write",
      timestamp: now,
      nonce: "req-nonce",
      signer_role: "AGENT",
    },
    over.secret ?? AGENT,
  );
}

function deps() {
  return { replayStore: new MemoryReplayStore(), revocationStore: new MemoryRevocationStore() };
}

describe("signed CAPABILITY_REQUEST", () => {
  it("ALLOW when agent-signed request matches subject", async () => {
    const result = await authorizeCapability(
      {
        envelope: envelope(),
        resolvedKey: ISSUER,
        issuerRole: "ISSUER",
        agentKey: AGENT,
        capabilityRequest: request(),
        delegation: delegation(),
        capability: getCapability("agicp.tool.bounded")!,
        requestedScope: "tool:bounded:write",
        policySnapshot: issuerEvaluation(now),
        now,
      },
      deps(),
    );
    assert.equal(result.decision, "ALLOW");
  });

  it("missing request => DENY CAPABILITY_REQUEST_MISSING", async () => {
    const result = await authorizeCapability(
      {
        envelope: envelope(),
        resolvedKey: ISSUER,
        issuerRole: "ISSUER",
        agentKey: AGENT,
        capabilityRequest: null,
        delegation: delegation(),
        capability: getCapability("agicp.tool.bounded")!,
        requestedScope: "tool:bounded:write",
        policySnapshot: issuerEvaluation(now),
        now,
      },
      deps(),
    );
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "CAPABILITY_REQUEST_MISSING");
  });

  it("observer-signed request => DENY", async () => {
    const forged = { ...request(), signer_role: "OBSERVER" as unknown as "AGENT" };
    const result = await authorizeCapability(
      {
        envelope: envelope(),
        resolvedKey: ISSUER,
        issuerRole: "ISSUER",
        agentKey: AGENT,
        capabilityRequest: forged,
        delegation: delegation(),
        capability: getCapability("agicp.tool.bounded")!,
        requestedScope: "tool:bounded:write",
        policySnapshot: issuerEvaluation(now),
        now,
      },
      deps(),
    );
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "CAPABILITY_REQUEST_OBSERVER_SIGNED");
  });

  it("wrong subject => DENY CAPABILITY_REQUEST_SUBJECT_MISMATCH", async () => {
    const result = await authorizeCapability(
      {
        envelope: envelope(),
        resolvedKey: ISSUER,
        issuerRole: "ISSUER",
        agentKey: AGENT,
        capabilityRequest: request({ subject: "other-agent" }),
        delegation: delegation(),
        capability: getCapability("agicp.tool.bounded")!,
        requestedScope: "tool:bounded:write",
        policySnapshot: issuerEvaluation(now),
        now,
      },
      deps(),
    );
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "CAPABILITY_REQUEST_SUBJECT_MISMATCH");
  });
});
