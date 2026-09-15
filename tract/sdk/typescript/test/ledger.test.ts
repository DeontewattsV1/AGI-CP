import test from "node:test";
import assert from "node:assert/strict";
import { computeEventHash, verifyChain, type EventReceiptInput } from "../src/ledger.js";

const genesis = `sha256:${"0".repeat(64)}`;

function event(previous_event_hash: string, event_id: string): EventReceiptInput {
  return {
    event_id,
    trace_id: "trace-1",
    agent_id: "agent:coder",
    parent_agent_id: "agent:root",
    action: {
      type: "filesystem.write",
      resource: "src/auth.ts",
      arguments_digest: `sha256:${"1".repeat(64)}`
    },
    authorization: {
      capability: "repo.write",
      decision: "ALLOW",
      policy: "tract-default-v1"
    },
    risk: { score: 0.1, classification: "NORMAL" },
    previous_event_hash,
    timestamp: "2026-09-14T21:00:00Z"
  };
}

test("valid chain verifies", () => {
  const one = event(genesis, "evt-1");
  const oneHash = computeEventHash(one);
  const two = event(oneHash, "evt-2");
  const twoHash = computeEventHash(two);
  assert.equal(verifyChain([{ ...one, event_hash: oneHash }, { ...two, event_hash: twoHash }], genesis), true);
});

test("tampering breaks replay verification", () => {
  const one = event(genesis, "evt-1");
  const oneHash = computeEventHash(one);
  const tampered = { ...one, action: { ...one.action, resource: "secrets.env" } };
  assert.equal(verifyChain([{ ...tampered, event_hash: oneHash }], genesis), false);
});
