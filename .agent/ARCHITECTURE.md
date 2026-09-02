# Architecture

AGI-CP is a fail-closed capability authorization protocol.

The TypeScript capability-gateway is role `E` (enforcement). It evaluates:

```
ALLOW ⇔ I ∧ K ∧ S ∧ D ∧ A ∧ T ∧ R ∧ P
```

AI platform adapters are transport only. They MUST NOT implement authorization.

Protocol guarantees are listed in `spec/AGI-CP-v0.2-ERRATA.md`. Passing tests are reference-implementation properties, not proof of containment.
