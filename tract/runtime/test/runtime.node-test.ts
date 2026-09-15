import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import { passportPayload, verifyPassport, type RuntimePassport } from "../auth/passport-verifier.ts";
import { RuntimeEventBus } from "../events/event-bus.ts";
import { ReceiptEmitter, receiptHash } from "../events/receipt-emitter.ts";
import { gitInterceptor, httpInterceptor, mcpInterceptor, shellInterceptor } from "../interceptors/concrete.ts";
import { inspectAll } from "../interceptors/types.ts";
import { LineageRevocationStore } from "../revocation/lineage-store.ts";

const keys = generateKeyPairSync("ed25519");
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const privateKey = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();

function signedPassport(): RuntimePassport {
  const passport: RuntimePassport = {
    tract_version: "0.1", subject: "agent:child", parent: "agent:root", purpose: "test",
    capabilities: ["repo.read"], prohibited: ["credential.read"], resources: ["repo:test"],
    delegation: { allowed: false, maximum_depth: 0, maximum_children: 0 },
    network: { default: "deny", allow: ["https://api.example.test"] },
    issued_at: "2026-09-15T00:00:00.000Z", expires_at: "2026-09-16T00:00:00.000Z",
    nonce: "nonce-123456", issuer: "tract://root", signature: "",
  };
  passport.signature = sign(null, passportPayload(passport), privateKey).toString("base64url");
  return passport;
}

test("valid Ed25519 passport verifies and tampering fails", () => {
  const passport = signedPassport();
  assert.equal(verifyPassport(passport, publicKey, Date.parse("2026-09-15T12:00:00Z")).valid, true);
  assert.equal(verifyPassport({ ...passport, purpose: "tampered" }, publicKey, Date.parse("2026-09-15T12:00:00Z")).valid, false);
});

test("expired passport fails closed", () => {
  assert.equal(verifyPassport(signedPassport(), publicKey, Date.parse("2026-09-17T00:00:00Z")).valid, false);
});

test("parent revocation reaches descendants", () => {
  const store = new LineageRevocationStore();
  store.register("agent:child", "agent:root"); store.register("agent:grandchild", "agent:child");
  store.revoke("agent:root", "operator revoke");
  assert.equal(store.isRevoked("agent:grandchild"), true);
});

test("interceptors deny unknown operations and resources", async () => {
  const base = { agentId: "a", passportId: "p", capability: "x", argumentsDigest: "sha256:x", timestamp: new Date().toISOString() };
  const git = gitInterceptor(new Set(["repo:test"]));
  assert.equal((await inspectAll({ ...base, surface: "git", resource: "repo:test", operation: "force_push" }, [git])).decision, "DENY");
  const http = httpInterceptor(new Set(["https://api.example.test"]));
  assert.equal((await inspectAll({ ...base, surface: "http", resource: "https://evil.example/path", operation: "GET" }, [http])).decision, "DENY");
  const shell = shellInterceptor(new Set(["npm test"]));
  assert.equal((await inspectAll({ ...base, surface: "shell", resource: "workspace", operation: "npm test" }, [shell])).decision, "ALLOW");
  const mcp = mcpInterceptor(new Set(["github.read"]));
  assert.equal((await inspectAll({ ...base, surface: "mcp", resource: "unknown.tool", operation: "call" }, [mcp])).decision, "DENY");
});

test("receipt is signed, hash stable, and event stream is read-only to consumers", () => {
  const bus = new RuntimeEventBus(); const seen: string[] = []; bus.stream.subscribe((event) => seen.push(event.event_hash));
  const input = {
    event_id: "evt-1", trace_id: "trace-1", agent_id: "agent:child", parent_agent_id: "agent:root",
    action: { type: "git.read", resource: "repo:test", arguments_digest: `sha256:${"a".repeat(64)}` },
    authorization: { capability: "repo.read", decision: "ALLOW" as const, policy: "tract-v0.2" },
    risk: { score: 0.1, classification: "NORMAL" as const }, previous_event_hash: `sha256:${"0".repeat(64)}`,
    timestamp: "2026-09-15T12:00:00.000Z",
  };
  const receipt = new ReceiptEmitter(privateKey, bus).emit(input);
  assert.equal(receipt.event_hash, receiptHash(input)); assert.equal(seen[0], receipt.event_hash);
  assert.equal(typeof (bus.stream as unknown as { publish?: unknown }).publish, "undefined");
});
