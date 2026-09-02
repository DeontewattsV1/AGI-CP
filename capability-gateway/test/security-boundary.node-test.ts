import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { authorizeCapability } from "../src/gateway/capability-gateway.ts";
import { signEnvelope } from "../src/auth/signature.ts";
import { MemoryReplayStore } from "../src/auth/replay.ts";
import { MemoryRevocationStore } from "../src/auth/revocation.ts";
import { getCapability } from "../src/capabilities/registry.ts";
import { combineDecisions } from "../src/capabilities/policy.ts";
import type { Delegation, SignedRequestEnvelope } from "../src/capabilities/types.ts";

const SECRET = "test-issuer-secret";
const now = Date.now();

function cap(id = "agicp.tool.bounded") {
  return getCapability(id)!;
}

function envelope(over: Partial<SignedRequestEnvelope> = {}): SignedRequestEnvelope {
  const base = {
    requestId: over.requestId ?? "req-1",
    timestamp: over.timestamp ?? now,
    issuer: over.issuer ?? "issuer-1",
    subject: over.subject ?? "agent-A17",
    capability: over.capability ?? "agicp.tool.bounded",
    delegationId: over.delegationId ?? "dlg-1",
    nonce: over.nonce ?? "nonce-1",
    payload: over.payload ?? {},
    signature: "",
  };
  const signed = over.signature ?? signEnvelope(base, SECRET);
  return { ...base, ...over, signature: signed };
}

function delegation(over: Partial<Delegation> = {}): Delegation {
  return {
    id: "dlg-1",
    issuer: "issuer-1",
    subject: "agent-A17",
    capabilities: ["agicp.tool.bounded"],
    scopes: ["tool:bounded:*"],
    issuedAt: now - 1000,
    expiresAt: now + 60_000,
    revoked: false,
    ...over,
  };
}

function stores() {
  return { replayStore: new MemoryReplayStore(), revocationStore: new MemoryRevocationStore() };
}

async function authorize(over: Record<string, unknown> = {}) {
  return authorizeCapability(
    {
      envelope: (over.envelope as SignedRequestEnvelope) ?? envelope(),
      resolvedKey: (over.resolvedKey as string | null | undefined) === undefined ? SECRET : (over.resolvedKey as string | null),
      issuerRole: (over.issuerRole as "ISSUER") ?? "ISSUER",
      delegation: ("delegation" in over ? over.delegation : delegation()) as Delegation | null,
      capability: ("capability" in over ? over.capability : cap()) as ReturnType<typeof cap> | null,
      requestedScope: (over.requestedScope as string) ?? "tool:bounded:write",
      now,
      deploymentAttestation: (over.deploymentAttestation as never) ?? null,
      extraVerifier: over.extraVerifier as undefined | (() => "ALLOW" | "DENY" | "INDETERMINATE"),
    },
    (over.deps as ReturnType<typeof stores>) ?? stores(),
  );
}

describe("Capability Security Boundary", () => {
  it("all required predicates pass => ALLOW", async () => {
    const result = await authorize();
    assert.equal(result.decision, "ALLOW");
  });
  it("missing identity => DENY IDENTITY_MISSING", async () => {
    const result = await authorize({ envelope: envelope({ issuer: "", subject: "" }) });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "IDENTITY_MISSING");
  });
  it("key cannot be resolved => DENY KEY_NOT_RESOLVED", async () => {
    const result = await authorize({ resolvedKey: null });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "KEY_NOT_RESOLVED");
  });
  it("invalid signature => DENY INVALID_SIGNATURE", async () => {
    const result = await authorize({ envelope: envelope({ signature: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }) });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "INVALID_SIGNATURE");
  });
  it("timestamp outside window => DENY TIMESTAMP_OUTSIDE_WINDOW", async () => {
    const result = await authorize({ envelope: envelope({ timestamp: now - 20 * 60 * 1000 }) });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "TIMESTAMP_OUTSIDE_WINDOW");
  });
  it("revocation control missing => DENY REVOCATION_CONTROL_MISSING", async () => {
    const result = await authorize({ deps: { replayStore: new MemoryReplayStore(), revocationStore: null } });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "REVOCATION_CONTROL_MISSING");
  });
  it("replay control missing => DENY REPLAY_CONTROL_MISSING", async () => {
    const result = await authorize({ deps: { replayStore: null, revocationStore: new MemoryRevocationStore() } });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "REPLAY_CONTROL_MISSING");
  });
  it("replayed nonce => DENY REPLAY_DETECTED", async () => {
    const deps = stores();
    const first = await authorize({ deps });
    assert.equal(first.decision, "ALLOW");
    const second = await authorize({ deps });
    assert.equal(second.decision, "DENY");
    assert.equal(second.reason, "REPLAY_DETECTED");
  });
  it("revoked delegation id => DENY REVOKED", async () => {
    const deps = stores();
    deps.revocationStore.revoke("dlg-1");
    const result = await authorize({ deps });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "REVOKED");
  });
  it("missing delegation => DENY DELEGATION_NOT_FOUND", async () => {
    const result = await authorize({ delegation: null });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "DELEGATION_NOT_FOUND");
  });
  it("observer key cannot authorize capability", async () => {
    const result = await authorize({ issuerRole: "OBSERVER" });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "OBSERVER_KEY_USED_AS_ISSUER");
  });
  it("SECURITY_CRITICAL lacks attestation => DENY", async () => {
    const c = cap("agicp.containment.modify");
    const result = await authorize({
      envelope: envelope({ capability: c.id }),
      capability: c,
      delegation: delegation({ capabilities: [c.id], scopes: ["containment:modify"] }),
      requestedScope: "containment:modify",
    });
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "DEPLOYMENT_ATTESTATION_MISSING");
  });
  it("policy combiner never promotes DENY or INDETERMINATE to ALLOW", () => {
    assert.equal(combineDecisions(["ALLOW", "DENY"]), "DENY");
    assert.equal(combineDecisions(["ALLOW", "INDETERMINATE"]), "INDETERMINATE");
    assert.equal(combineDecisions(["ALLOW", "ALLOW"]), "ALLOW");
  });
});
