import test from "node:test";
import assert from "node:assert/strict";
import { classifyRisk, isExpired, validateDelegation, type AgentPassport } from "../src/policy.js";

const parent: AgentPassport = {
  tract_version: "0.1",
  subject: "agent:root",
  purpose: "repository maintenance",
  capabilities: ["repo.read", "repo.write"],
  resources: ["repo:example/project"],
  delegation: { allowed: true, maximum_depth: 2, maximum_children: 4 },
  network: { default: "deny", allow: ["api.github.com"] },
  issued_at: "2026-09-14T20:00:00Z",
  expires_at: "2026-09-15T20:00:00Z",
  nonce: "nonce-parent",
  issuer: "tract://authority/root",
  signature: "sig-parent"
};

test("child cannot widen capabilities", () => {
  const child: AgentPassport = {
    ...parent,
    subject: "agent:child",
    parent: parent.subject,
    capabilities: ["repo.read", "repo.write", "credential.read"],
    delegation: { allowed: false, maximum_depth: 1, maximum_children: 0 },
    nonce: "nonce-child",
    signature: "sig-child"
  };
  assert.equal(validateDelegation(parent, child), "DENY");
});

test("strictly narrower child is allowed", () => {
  const child: AgentPassport = {
    ...parent,
    subject: "agent:child",
    parent: parent.subject,
    capabilities: ["repo.read"],
    delegation: { allowed: false, maximum_depth: 1, maximum_children: 0 },
    nonce: "nonce-child",
    signature: "sig-child"
  };
  assert.equal(validateDelegation(parent, child), "ALLOW");
});

test("risk bands are deterministic", () => {
  assert.equal(classifyRisk(0.1), "NORMAL");
  assert.equal(classifyRisk(0.3), "OBSERVE");
  assert.equal(classifyRisk(0.6), "RESTRICT");
  assert.equal(classifyRisk(0.8), "QUARANTINE");
  assert.equal(classifyRisk(0.9), "TERMINATE");
});

test("expiry fails closed", () => {
  assert.equal(isExpired(parent, new Date("2026-09-16T00:00:00Z")), true);
});
