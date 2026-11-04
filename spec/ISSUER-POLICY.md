# Issuer policy re-evaluation (AGI-CP v0.2 §2.5)

Trace: A12.

An issuer MUST re-evaluate policy predicates.
An issuer MUST NOT be a signature oracle for adjudications.

## Snapshot

```
PolicySnapshot {
  policyVersion
  evaluatedAt
  predicates: { scope_allowed, risk_allowed, fresh, ... }
  source = ISSUER_EVALUATION
}
```

## Rules

1. A valid issuer envelope signature is not policy.
2. An imported ALLOW adjudication without a fresh ISSUER_EVALUATION snapshot is ISSUER_SIGNATURE_ORACLE.
3. Missing snapshot is POLICY_NOT_REEVALUATED.
4. Any required predicate not strictly true is POLICY_DENIED.
5. Policy version must match the current published version.
