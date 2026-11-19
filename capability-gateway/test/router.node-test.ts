import assert from "node:assert/strict";
import { it } from "node:test";
import { buildServer, type AuthorizationInputs, type InvokeBody } from "../src/api/router.ts";
import { signEnvelope } from "../src/auth/signature.ts";
import { makeCapabilityRequest } from "../src/auth/capability-request.ts";
import { issuerEvaluation } from "../src/auth/issuer-policy.ts";
import { makeIssuerProof } from "../src/auth/issuer-proof.ts";

function fixture() {
  const now = Date.now();
  const envelope = {
    requestId: "http-request", timestamp: now, issuer: "issuer", subject: "agent",
    capability: "agicp.tool.bounded", delegationId: "delegation", nonce: "nonce",
    payload: {}, signature: "",
  };
  envelope.signature = signEnvelope(envelope, "issuer-test-key");
  const body: InvokeBody = {
    envelope, requestedScope: "tool:bounded:write",
    capabilityRequest: makeCapabilityRequest({
      request_id: envelope.requestId, subject: envelope.subject,
      capability: envelope.capability, scope: "tool:bounded:write",
      timestamp: now, nonce: "agent-nonce", signer_role: "AGENT",
    }, "agent-test-key"),
  };
  const trusted: AuthorizationInputs = {
    resolvedKey: "issuer-test-key", issuerRole: "ISSUER", agentKey: "agent-test-key",
    policySnapshot: issuerEvaluation(now),
    issuerProof: makeIssuerProof({
      requestId: envelope.requestId,
      subject: envelope.subject,
      capability: envelope.capability,
      signerRole: "ISSUER",
    }, "issuer-test-key"),
    delegation: {
      id: "delegation", issuer: "issuer", subject: "agent",
      capabilities: [envelope.capability], scopes: ["tool:bounded:*"],
      issuedAt: now - 1000, expiresAt: now + 60000, revoked: false,
    },
  };
  return { body, trusted };
}

it("HTTP forwards request and trusted authorization, then rejects replay", async t => {
  const { body, trusted } = fixture();
  const app = await buildServer({ resolveAuthorization: async input => {
    assert.deepEqual(input, body);
    return trusted;
  } });
  t.after(() => app.close());
  const first = await app.inject({ method: "POST", url: "/plugin/invoke", payload: body });
  assert.equal(first.statusCode, 200);
  assert.equal(first.json().decision, "ALLOW");
  const second = await app.inject({ method: "POST", url: "/plugin/invoke", payload: body });
  assert.equal(second.statusCode, 403);
  assert.equal(second.json().reason, "REPLAY_DETECTED");
});

it("caller-supplied keys and policy cannot authorize an unconfigured server", async t => {
  const { body, trusted } = fixture();
  const app = await buildServer();
  t.after(() => app.close());
  const result = await app.inject({ method: "POST", url: "/plugin/invoke", payload: { ...body, ...trusted } });
  assert.equal(result.statusCode, 403);
  assert.equal(result.json().reason, "AUTHORIZATION_MISSING");
});

for (const [name, override, expected] of [
  ["missing policy", { policySnapshot: null }, "POLICY_NOT_REEVALUATED"],
  ["failed policy", { policySnapshot: issuerEvaluation(Date.now(), { risk_allowed: false }) }, "POLICY_DENIED"],
  ["missing agent key", { agentKey: null }, "CAPABILITY_REQUEST_INVALID_SIGNATURE"],
  ["observer issuer", { issuerRole: "OBSERVER" }, "OBSERVER_KEY_USED_AS_ISSUER"],
  ["imported allow without evaluation", { policySnapshot: null, importedAdjudication: { decision: "ALLOW", signerRole: "JUDGE" } }, "ISSUER_SIGNATURE_ORACLE"],
] as const) {
  it(`HTTP denies ${name} despite forged body assertions`, async t => {
    const { body, trusted } = fixture();
    const app = await buildServer({ resolveAuthorization: async input => {
      assert.deepEqual(input, body);
      assert.equal("resolvedKey" in input, false);
      assert.equal("policySnapshot" in input, false);
      return { ...trusted, ...override };
    } });
    t.after(() => app.close());
    const result = await app.inject({ method: "POST", url: "/plugin/invoke", payload: { ...body, ...trusted } });
    assert.equal(result.statusCode, 403);
    assert.equal(result.json().decision, "DENY");
    assert.equal(result.json().reason, expected);
  });
}

it("HTTP rejects a resolver delegation for a different envelope ID", async t => {
  const { body, trusted } = fixture();
  const app = await buildServer({ resolveAuthorization: async () => ({
    ...trusted,
    delegation: { ...trusted.delegation!, id: "another-delegation" },
  }) });
  t.after(() => app.close());
  const result = await app.inject({ method: "POST", url: "/plugin/invoke", payload: body });
  assert.equal(result.statusCode, 403);
  assert.equal(result.json().reason, "DELEGATION_NOT_FOUND");
});

it("HTTP denies resolver failure without exposing exception details", async t => {
  const { body } = fixture();
  const app = await buildServer({ resolveAuthorization: async () => { throw new Error("private backend detail"); } });
  t.after(() => app.close());
  const result = await app.inject({ method: "POST", url: "/plugin/invoke", payload: body });
  assert.equal(result.statusCode, 403);
  assert.deepEqual(result.json(), { decision: "DENY", reason: "AUTHORIZATION_MISSING" });
});

it("HTTP denies a missing capability request", async t => {
  const { body, trusted } = fixture();
  delete body.capabilityRequest;
  const app = await buildServer({ resolveAuthorization: async () => trusted });
  t.after(() => app.close());
  const result = await app.inject({ method: "POST", url: "/plugin/invoke", payload: body });
  assert.equal(result.statusCode, 403);
  assert.equal(result.json().reason, "CAPABILITY_REQUEST_MISSING");
});

it("HTTP rejects malformed authorization fields before invoking the resolver", async t => {
  const { body } = fixture();
  let resolverCalled = false;
  const app = await buildServer({ resolveAuthorization: async () => {
    resolverCalled = true;
    return null;
  } });
  t.after(() => app.close());
  const malformed = {
    ...body,
    capabilityRequest: { ...body.capabilityRequest!, signature: "é".repeat(64) },
  };
  const result = await app.inject({ method: "POST", url: "/plugin/invoke", payload: malformed });
  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.json(), { decision: "DENY", reason: "AUTHORIZATION_MISSING" });
  assert.equal(resolverCalled, false);
});

it("HTTP rejects malformed envelopes before invoking the resolver", async t => {
  const { body } = fixture();
  let resolverCalled = false;
  const app = await buildServer({ resolveAuthorization: async () => {
    resolverCalled = true;
    return null;
  } });
  t.after(() => app.close());
  const malformed = { ...body, envelope: { ...body.envelope, timestamp: "not-a-number" } };
  const result = await app.inject({ method: "POST", url: "/plugin/invoke", payload: malformed });
  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.json(), { decision: "DENY", reason: "AUTHORIZATION_MISSING" });
  assert.equal(resolverCalled, false);
});
