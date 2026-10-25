# AGI-CP

Artificial General Intelligence Containment Protocol.

This repository is a research standard and a reference enforcement gateway. It does **not** claim to contain arbitrary AGI.

## What is specified

- Fail-closed capability authorization
- Separation `O ≠ J ≠ U ≠ E ≠ R`
- `ALLOW ⇔ I ∧ K ∧ S ∧ D ∧ A ∧ T ∧ R ∧ P`
- DENY and INDETERMINATE never become ALLOW

Normative errata: [`spec/AGI-CP-v0.2-ERRATA.md`](spec/AGI-CP-v0.2-ERRATA.md)

## Enforcement runtime

```
capability-gateway/
```

The gateway is role `E`. Observer keys cannot mint capability.

```bash
cd capability-gateway
npm install
npm test
```

## Claim hierarchy

Protocol invariant ⊂ reference implementation property ⊂ deployment assumption ⊂ empirical security claim.

A passing test suite is the second layer only.

## License

MIT
