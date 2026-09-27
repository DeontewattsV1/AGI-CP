import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { collectEvidence, decideEvidence, dropNonSatisfied } from "../src/auth/evidence.ts";
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
const window = {
  requestId: "req-ev-1",
  start: now - 1000,
  end: now + 1000,
  expectedObserverIds: ["obs-1", "obs-2"],
};

describe("evidence slots", () => {
  it("missing expected observer is UNVERIFIABLE and stays in the set", () => {
    const slots = collectEvidence(window, [
      { observerId: "obs-1", requestId: "req-ev-1", observedAt: now, state: "SATISFIED" },
    ]);
    assert.equal(slots.length, 2);
    assert.equal(slots.find((s) => s.observerId === "obs-2")?.state, "UNVERIFIABLE");
    assert.equal(decideEvidence(slots), "EVIDENCE_UNVERIFIABLE");
  });
  it("dropping UNVERIFIABLE slots would fake ALLOW and the gate must not do that", () => {
    const slots = collectEvidence(window, [
      { observerId: "obs-1", requestId: "req-ev-1", observedAt: now, state: "SATISFIED" },
    ]);
    assert.equal(decideEvidence(dropNonSatisfied(slots)), "ok");
    assert.equal(decideEvidence(slots), "EVIDENCE_UNVERIFIABLE");
  });
});

function envelope(): SignedRequestEnvelope {
  const base = {
    requestId: "req-ev-1",
    timestamp: now,
    issuer: "issuer-1",
    subject: "agent-A17",
    capability: "agicp.tool.bounded",
    delegationId: "dlg-1",
    nonce: "nonce-ev-1",
    payload: {},
    signature: "",
  };
  return { ...base, signature: signEnvelope(base, ISSUER) };
}

function ctx() {
  return {
    envelope: envelope(),
    resolvedKey: ISSUER,
    issuerRole: "ISSUER" as const,
    agentKey: AGENT,
    policySnapshot: issuerEvaluation(now),
    capabilityRequest: makeCapabilityRequest({
      request_id: "req-ev-1",
      subject: "agent-A17",
      capability: "agicp.tool.bounded",
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

describe("gateway evidence window", () => {
  it("missing observation is INDETERMINATE, not ALLOW", async () => {
    const result = await authorizeCapability({
      ...ctx(),
      evidenceWindow: window,
      observations: [{ observerId: "obs-1", requestId: "req-ev-1", observedAt: now, state: "SATISFIED" }],
    }, { replayStore: new MemoryReplayStore(), revocationStore: new MemoryRevocationStore() });
    assert.equal(result.decision, "INDETERMINATE");
    assert.equal(result.reason, "EVIDENCE_UNVERIFIABLE");
  });
  it("all expected observers SATISFIED may ALLOW", async () => {
    const result = await authorizeCapability({
      ...ctx(),
      evidenceWindow: window,
      observations: [
        { observerId: "obs-1", requestId: "req-ev-1", observedAt: now, state: "SATISFIED" },
        { observerId: "obs-2", requestId: "req-ev-1", observedAt: now, state: "SATISFIED" },
      ],
    }, { replayStore: new MemoryReplayStore(), revocationStore: new MemoryRevocationStore() });
    assert.equal(result.decision, "ALLOW");
  });
});
