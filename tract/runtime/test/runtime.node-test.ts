import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { passportPayload, verifyPassport, type RuntimePassport } from "../auth/passport-verifier.ts";
import { RuntimeEventBus } from "../events/event-bus.ts";
import { ReceiptEmitter, receiptHash, verifyReceiptHash } from "../events/receipt-emitter.ts";
import { gitInterceptor, httpInterceptor, mcpInterceptor, shellInterceptor } from "../interceptors/concrete.ts";
import { inspectAll, type AuthorizationEvidence } from "../interceptors/types.ts";
import { LineageRevocationStore } from "../revocation/lineage-store.ts";

const keys = generateKeyPairSync("ed25519");
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const privateKey = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();

function signedPassport(): RuntimePassport {
  const passport: RuntimePassport = {
    tract_version: "0.1",
    subject: "agent:child",
    parent: "agent:root",
    purpose: "test",
    capabilities: ["repo.read"],
    prohibited: ["credential.read"],
    resources: ["repo:test"],
    delegation: { allowed: false, maximum_depth: 0, maximum_children: 0 },
    network: { default: "deny", allow: ["https://api.example.test"] },
    issued_at: "2026-09-15T00:00:00.000Z",
    expires_at: "2026-09-16T00:00:00.000Z",
    nonce: "nonce-123456",
    issuer: "tract://root",
    signature: "",
  };
  passport.signature = sign(null, passportPayload(passport), privateKey).toString("base64url");
  return passport;
}

const allowEvidence = (capability: string): AuthorizationEvidence => ({
  passportVerified: true,
  gatewayDecision: "ALLOW",
  authorizedSubject: "agent:child",
  authorizedCapability: capability,
});

test("valid Ed25519 passport verifies and tampering fails", () => {
  const passport = signedPassport();
  assert.equal(verifyPassport(passport, publicKey, Date.parse("2026-09-15T12:00:00Z")).valid, true);
  assert.equal(verifyPassport({ ...passport, purpose: "tampered" }, publicKey, Date.parse("2026-09-15T12:00:00Z")).valid, false);
});

test("passport verifier rejects malformed schema, invalid clocks and wrong key types", () => {
  const passport = signedPassport();
  assert.equal(verifyPassport({ ...passport, tract_version: "9" }, publicKey, Date.parse("2026-09-15T12:00:00Z")).valid, false);
  assert.equal(verifyPassport(passport, publicKey, Number.NaN).valid, false);
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" }).toString();
  assert.equal(verifyPassport(passport, rsa, Date.parse("2026-09-15T12:00:00Z")).valid, false);
});

test("expired passport fails closed", () => {
  assert.equal(verifyPassport(signedPassport(), publicKey, Date.parse("2026-09-17T00:00:00Z")).valid, false);
});

test("parent revocation reaches descendants", () => {
  const store = new LineageRevocationStore();
  store.register("agent:child", "agent:root");
  store.register("agent:grandchild", "agent:child");
  store.revoke("agent:root", "operator revoke");
  assert.equal(store.isRevoked("agent:grandchild"), true);
});

test("interceptors require verified gateway authority before surface policy", async () => {
  const base = {
    agentId: "agent:child",
    passportId: "passport:1",
    argumentsDigest: "sha256:x",
    timestamp: new Date().toISOString(),
  };

  const shell = shellInterceptor(new Set(["npm test"]));
  const denied = await inspectAll({
    ...base,
    surface: "shell",
    capability: "shell.exec",
    resource: "workspace",
    operation: "npm test",
    authorization: { ...allowEvidence("shell.exec"), gatewayDecision: "DENY" },
  }, [shell]);
  assert.equal(denied.decision, "DENY");

  const mismatch = await inspectAll({
    ...base,
    surface: "shell",
    capability: "shell.exec",
    resource: "workspace",
    operation: "npm test",
    authorization: allowEvidence("repo.read"),
  }, [shell]);
  assert.equal(mismatch.decision, "DENY");

  const allowed = await inspectAll({
    ...base,
    surface: "shell",
    capability: "shell.exec",
    resource: "workspace",
    operation: "npm test",
    authorization: allowEvidence("shell.exec"),
  }, [shell]);
  assert.equal(allowed.decision, "ALLOW");
});

test("Git HTTP and MCP mediators deny unauthorized operations or resources", async () => {
  const common = {
    agentId: "agent:child",
    passportId: "passport:1",
    argumentsDigest: "sha256:x",
    timestamp: new Date().toISOString(),
  };

  const git = gitInterceptor(new Set(["repo:test"]));
  assert.equal((await inspectAll({
    ...common, surface: "git", capability: "git.write", resource: "repo:test", operation: "force_push",
    authorization: allowEvidence("git.write"),
  }, [git])).decision, "DENY");

  const http = httpInterceptor(new Set(["https://api.example.test"]));
  assert.equal((await inspectAll({
    ...common, surface: "http", capability: "http.request", resource: "https://evil.example/path", operation: "GET",
    authorization: allowEvidence("http.request"),
  }, [http])).decision, "DENY");

  const mcp = mcpInterceptor(new Set(["github.read"]));
  assert.equal((await inspectAll({
    ...common, surface: "mcp", capability: "mcp.tool", resource: "unknown.tool", operation: "call",
    authorization: allowEvidence("mcp.tool"),
  }, [mcp])).decision, "DENY");
});

test("event bus isolates observer failures and bounds retention", () => {
  let observerErrors = 0;
  const bus = new RuntimeEventBus(2, () => observerErrors++);
  const delivered: string[] = [];
  bus.stream.subscribe(() => { throw new Error("observer failure"); });
  bus.stream.subscribe((event) => delivered.push(event.event_id));

  for (let i = 0; i < 3; i++) {
    bus.publish({
      event_id: `evt-${i}`, trace_id: "trace", agent_id: "agent:child",
      capability: "repo.read", decision: "ALLOW", risk: 0,
      previous_event_hash: `sha256:${"0".repeat(64)}`,
      event_hash: `sha256:${String(i).padStart(64, "0")}`,
      timestamp: "2026-09-15T12:00:00.000Z",
    });
  }

  assert.equal(observerErrors, 3);
  assert.deepEqual(delivered, ["evt-0", "evt-1", "evt-2"]);
  assert.deepEqual(bus.stream.snapshot().map((event) => event.event_id), ["evt-1", "evt-2"]);
});

test("receipt emitter owns predecessor chain and publishes reconstructable events", () => {
  const bus = new RuntimeEventBus();
  const seen: string[] = [];
  bus.stream.subscribe((event) => seen.push(`${event.previous_event_hash}->${event.event_hash}`));
  const emitter = new ReceiptEmitter(privateKey, bus);

  const draft = {
    trace_id: "trace-1",
    agent_id: "agent:child",
    parent_agent_id: "agent:root",
    action: { type: "git.read", resource: "repo:test", arguments_digest: `sha256:${"a".repeat(64)}` },
    authorization: { capability: "repo.read", decision: "ALLOW" as const, policy: "tract-v0.2" },
    risk: { score: 0.1, classification: "NORMAL" as const },
    timestamp: "2026-09-15T12:00:00.000Z",
  };

  const first = emitter.emit({ ...draft, event_id: "evt-1" });
  const second = emitter.emit({ ...draft, event_id: "evt-2" });

  assert.equal(first.previous_event_hash, `sha256:${"0".repeat(64)}`);
  assert.equal(second.previous_event_hash, first.event_hash);
  assert.equal(verifyReceiptHash(first), true);
  assert.equal(verifyReceiptHash(second), true);
  assert.equal(first.event_hash, receiptHash({
    ...draft, event_id: "evt-1", previous_event_hash: `sha256:${"0".repeat(64)}`,
  }));
  assert.equal(seen[1], `${first.event_hash}->${second.event_hash}`);
  assert.equal(typeof (bus.stream as unknown as { publish?: unknown }).publish, "undefined");
});
