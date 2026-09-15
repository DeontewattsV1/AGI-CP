# TRACT v0.1 — Traceable Runtime Authorization & Capability Trust

Status: Draft reference protocol layered on AGI-CP v0.2 errata.

## Purpose

TRACT makes consequential AI and micro-agent actions attributable, bounded, interruptible, replayable, and tamper-evident. It does not attempt to infer whether an agent is metaphysically malicious. It evaluates observable behavior against explicit authority.

## Governing invariant

> No consequential AI action without attributable identity, bounded authority, observable execution, and verifiable provenance.

TRACT extends AGI-CP without collapsing its role separation:

`O ≠ J ≠ U ≠ E ≠ R`

Execution is permitted only when the underlying AGI-CP authorization predicates are satisfied and TRACT provenance predicates also hold:

`EXECUTE ⇔ I ∧ K ∧ S ∧ D ∧ A ∧ T ∧ R ∧ P ∧ V ∧ L ∧ Q`

Where:

- `V` = cryptographic provenance is valid.
- `L` = delegation lineage is intact and non-expanding.
- `Q` = requested action remains within declared purpose and current policy.

Therefore:

`¬V ∨ ¬L ∨ ¬Q ⇒ EXECUTE = 0`

UNKNOWN, STALE, CONFLICTING, UNVERIFIABLE, missing telemetry, broken lineage, or expired authority are closed states and MUST NOT become ALLOW.

## Authority monotonicity

For every delegated child:

`Capabilities(child) ⊆ Capabilities(parent)`

`Resources(child) ⊆ Resources(parent)`

`Network(child) ⊆ Network(parent)`

`Authority(child) ≤ Authority(parent) ≤ Authority(root-human-or-org)`

A child MUST NOT manufacture authority that the parent does not possess. Parent revocation MUST invalidate all descendant credentials.

## Agent Passport

Every executable principal SHOULD possess a short-lived signed Agent Passport containing at minimum:

```json
{
  "tract_version": "0.1",
  "subject": "agent:researcher:01942",
  "parent": "agent:orchestrator:00017",
  "model": {
    "provider": "declared-at-runtime",
    "model": "declared-at-runtime"
  },
  "purpose": "analyze repository dependencies",
  "capabilities": ["repo.read", "dependency.inspect"],
  "prohibited": [
    "credential.read",
    "repo.force_push",
    "persistence.install",
    "shell.network.raw"
  ],
  "resources": ["repo:example/project"],
  "delegation": {
    "allowed": true,
    "maximum_depth": 2,
    "maximum_children": 4
  },
  "network": {
    "default": "deny",
    "allow": ["api.github.com"]
  },
  "expires_at": "2026-09-15T05:00:00Z",
  "nonce": "01K...",
  "issuer": "tract://authority/root",
  "signature": "..."
}
```

The raw provider credential SHOULD remain outside the agent boundary and SHOULD be injected only by the execution mediator after authorization.

## Event Receipt

Every consequential action MUST emit an event receipt before or atomically with execution:

```json
{
  "event_id": "evt_01...",
  "trace_id": "trace_01...",
  "agent_id": "agent:coder:004",
  "parent_agent_id": "agent:architect:001",
  "action": {
    "type": "filesystem.write",
    "resource": "src/auth.ts",
    "arguments_digest": "sha256:..."
  },
  "authorization": {
    "capability": "repo.write",
    "decision": "ALLOW",
    "policy": "tract-default-v1"
  },
  "risk": {
    "score": 0.12,
    "classification": "NORMAL"
  },
  "previous_event_hash": "sha256:...",
  "event_hash": "sha256:...",
  "signature": "..."
}
```

The event chain is:

`H_n = H(H_{n-1} || E_n || AgentID || Capability || Decision)`

The ledger is tamper-evident, not magically immutable. Evidence commitments authenticate integrity, not truth.

## Three containment outcomes

TRACT preserves AGI-CP's distinction between:

- `U_token`: unauthorized token issuance.
- `U_gateway`: unauthorized gateway activation.
- `U_world`: unauthorized effect outside the gateway.

A deployment MUST NOT report `U_token = 0` as proof that `U_world = 0`.

## Observable mischief signals

Detectors MAY score behavior, but policy authority remains deterministic. Recommended signals include:

- unauthorized process or shell execution;
- credential or secret access;
- privilege escalation;
- unexpected outbound network connections;
- persistence installation;
- security-control disabling;
- destructive repository mutations;
- prompt-injection propagation into privileged tools;
- unauthorized agent spawning;
- capability laundering through child agents;
- suspicious shared-state coordination;
- unusual data transfer or exfiltration indicators;
- identity spoofing;
- audit-log alteration or deletion attempts.

A reference risk score MAY use:

`R_t = w1*P_t + w2*E_t + w3*X_t + w4*D_t + w5*T_t + w6*B_t`

with deployment-defined weights for policy violation, escalation, exfiltration, delegation anomaly, taint propagation, and behavioral deviation.

Suggested response bands:

| Risk | State | Default response |
|---|---|---|
| 0.00–0.25 | NORMAL | allow within passport |
| 0.25–0.50 | OBSERVE | increase telemetry |
| 0.50–0.70 | RESTRICT | narrow capabilities |
| 0.70–0.85 | QUARANTINE | sever external authority |
| 0.85–1.00 | TERMINATE | revoke and require human review |

LLM classifiers MAY assist detection but MUST NOT override fail-closed policy.

## Components

1. Root Identity Authority — human, organization, service, and agent identities.
2. Passport Issuer — signs bounded short-lived capabilities.
3. AGI-CP Authorization Gateway — re-evaluates policy predicates and refuses unknown states.
4. Behavioral Defense Adapter — Ethos Aegis threat/taint/guardrail signals.
5. Execution Mediator — shell, Git, HTTP, database, filesystem, MCP and tool calls.
6. TRACT Ledger — append-only logical event stream with hash chaining and signatures.
7. Mischief/Compromise Engine — deterministic and statistical detectors.
8. Response Controller — allow, restrict, quarantine, terminate, revoke, or hold for human approval.
9. Live Lineage Graph — visualization only; it MUST NOT be an authority source.

## Visualization semantics

Each node represents an authenticated principal. Each edge represents delegated authority. Each pulse represents a real event receipt.

Suggested states:

- GREEN — active and within authority.
- YELLOW — elevated observation.
- ORANGE — restricted.
- RED — denied or quarantined action.
- BLACK — unknown or unverifiable principal.
- severed edge — revocation.

## Security boundary

TRACT is a defensive governance and provenance system. The reference implementation MUST NOT provide offensive exploitation automation, credential theft, persistence mechanisms, evasion tooling, or malware deployment functionality. Adversarial tests SHOULD use synthetic fixtures or isolated sandboxes.

## Integration mapping

- AGI-CP: constitutional authorization semantics and fail-closed gateway.
- Ethos Aegis: behavioral defense, taint analysis, threat memory, guardrails, verification and sandbox adapters.
- Mise Brigade de Repo: operational Git/repository mutation policy and explicit apply gates.
- traceability-matrix: claim/evidence/requirement linkage.
- SOVEREIGN-LATTICE-GOVCORE and ALETHEIA-LATTICE: governance and evidence-integrity constraints.
- self-improving-agent: learning signals only; learned behavior cannot mint authority.
- mise-salt-shakers and Git-it-Got-it-Good: reusable workflow/policy adapters.
- Linguistic-Encryption-System-Celestial-: policy/evidence encoding experiments, provided decoding remains auditable.
- phaseform_runtime_package_v6 and Mise-Enhanced-GPU-Pack-a-Punch: runtime scheduling and high-compute lanes under the same passport/receipt boundary.

## Conformance requirements

A TRACT-conformant runtime MUST demonstrate:

1. invalid or missing passport ⇒ DENY/HOLD;
2. expired passport ⇒ DENY;
3. child authority widening ⇒ DENY;
4. parent revocation ⇒ descendant revocation;
5. unapproved network domain ⇒ DENY;
6. unavailable required telemetry ⇒ UNVERIFIABLE ⇒ DENY/HOLD;
7. event hash mutation ⇒ replay verification failure;
8. detector output alone cannot mint capability;
9. observer key cannot authorize execution;
10. audit deletion attempt emits a separate security event and cannot silently erase prior receipts.
