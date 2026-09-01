import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MemoryRevocationStore, revocationMessage } from "../src/auth/revocation.ts";
import { authorizeCapability } from "../src/gateway/capability-gateway.ts";
import { signEnvelope } from "../src/auth/signature.ts";
import { MemoryReplayStore } from "../src/auth/replay.ts";
import { getCapability } from "../src/capabilities/registry.ts";
import type { Delegation, SignedRequestEnvelope } from "../src/capabilities/types.ts";

const SECRET = "test-issuer-secret";
const now = Date.now();

function envelope(over: Partial<SignedRequestEnvelope> = {}): SignedRequestEnvelope {
  const base = {
    requestId: over.requestId ?? "req-child",
    timestamp: over.timestamp ?? now,
    issuer: over.issuer ?? "issuer-1",
    subject: over.subject ?? "agent-A17",
    capability: over.capability ?? "agicp.tool.bounded",
    delegationId: over.delegationId ?? "dlg-child",
    nonce: over.nonce ?? "nonce-child",
    payload: {},
    signature: "",
  };
  return { ...base, ...over, signature: over.signature ?? signEnvelope(base, SECRET) };
}

function childDelegation(): Delegation {
  return {
    id: "dlg-child",
    issuer: "issuer-1",
    subject: "agent-A17",
    capabilities: ["agicp.tool.bounded"],
    scopes: ["tool:bounded:*"],
    issuedAt: now - 1000,
    expiresAt: now + 60_000,
    revoked: false,
    parentId: "dlg-parent",
  };
}

describe("REVOCATION lineage", () => {
  it("parent revoke marks registered child revoked", async () => {
    const store = new MemoryRevocationStore();
    store.registerLineage("dlg-child", "dlg-parent");
    await store.apply(
      revocationMessage({
        revocation_id: "rev-1",
        target_id: "dlg-parent",
        reason: "EMERGENCY_STOP",
        issued_at: now,
        issuer_id: "enf-1",
        issuer_role: "ENFORCER",
      }),
    );
    assert.equal(await store.isRevoked("dlg-parent"), true);
    assert.equal(await store.isRevoked("dlg-child"), true);
    assert.equal(await store.isRevoked("dlg-unrelated"), false);
  });

  it("gateway denies child after parent REVOCATION without agent CRL", async () => {
    const revocationStore = new MemoryRevocationStore();
    revocationStore.registerLineage("dlg-child", "dlg-parent");
    await revocationStore.apply(
      revocationMessage({
        revocation_id: "rev-2",
        target_id: "dlg-parent",
        reason: "IDENTITY_REVOCATION",
        issued_at: now,
        issuer_id: "enf-1",
        issuer_role: "ENFORCER",
      }),
    );
    const result = await authorizeCapability(
      {
        envelope: envelope(),
        resolvedKey: SECRET,
        issuerRole: "ISSUER",
        delegation: childDelegation(),
        capability: getCapability("agicp.tool.bounded")!,
        requestedScope: "tool:bounded:write",
        now,
      },
      { replayStore: new MemoryReplayStore(), revocationStore },
    );
    assert.equal(result.decision, "DENY");
    assert.equal(result.reason, "REVOKED");
  });

  it("failed request does not burn nonce for a later valid request", async () => {
    const replayStore = new MemoryReplayStore();
    const revocationStore = new MemoryRevocationStore();
    const denied = await authorizeCapability(
      {
        envelope: envelope({ requestId: "req-retry", nonce: "n-retry" }),
        resolvedKey: SECRET,
        issuerRole: "ISSUER",
        delegation: null,
        capability: getCapability("agicp.tool.bounded")!,
        requestedScope: "tool:bounded:write",
        now,
      },
      { replayStore, revocationStore },
    );
    assert.equal(denied.decision, "DENY");
    const allowed = await authorizeCapability(
      {
        envelope: envelope({ requestId: "req-retry", nonce: "n-retry" }),
        resolvedKey: SECRET,
        issuerRole: "ISSUER",
        delegation: childDelegation(),
        capability: getCapability("agicp.tool.bounded")!,
        requestedScope: "tool:bounded:write",
        now,
      },
      { replayStore, revocationStore },
    );
    assert.equal(allowed.decision, "ALLOW");
  });
});
