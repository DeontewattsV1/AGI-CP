# REVOCATION (AGI-CP v0.2 §5)

Normative addendum. Trace: A15, A21, A22.

## Message

```
REVOCATION {
  protocol_version: "0.2.0"
  message_type: "REVOCATION"
  revocation_id
  target_id
  parent_id?
  reason
  issued_at
  issuer_id
  issuer_role ∈ {ISSUER, ENFORCER, HUMAN_AUTHORITY, RECORDER}
}
```

## Rules

1. The enforcement store MUST apply REVOCATION itself. The agent MUST NOT be the only CRL channel.
2. registerLineage(child, parent) MUST be recorded when a delegation with parentId is admitted.
3. Applying revocation to parent MUST mark registered descendants PARENT_REVOKED.
4. Default acceptance window is 5000 ms after issued_at. Deployments MUST publish their window.
5. HUMAN_AUTHORITY MAY issue REVOCATION. It MUST NOT mint C2+ tokens.
