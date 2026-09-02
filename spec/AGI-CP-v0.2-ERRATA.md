# AGI-CP v0.2 Errata Patch

Status: Normative errata against AGI-CP v0.1  
Change-control boundary: red-team attacks A1–A32, invariants I7/I8, conformance gaps  
Architecture: unchanged (`O ≠ J ≠ U ≠ E ≠ R`)

This document does not add new subsystems. It converts identified attacks into MUST / MUST NOT / SHOULD language.

Claim hierarchy (MUST NOT be inverted):

```
Protocol invariant ⊂ Reference implementation property ⊂ Deployment assumption ⊂ Empirical security claim
```

A green test suite MUST NOT promote a reference-implementation property into a protocol invariant.

---

## 1. Decision semantics

Trace: A6, A7, A8, I2

1. The six epistemic states SATISFIED, FAILED, UNKNOWN, STALE, CONFLICTING, UNVERIFIABLE MUST all participate in `D(F)`.
2. The required-predicate set MUST be fixed before quorum evaluation.
3. Quorum logic MUST NOT delete UNKNOWN, STALE, CONFLICTING, or UNVERIFIABLE from the required set in order to reach ALLOW.
4. Section 4 m-of-n applies to issuer keys `Q_U` only. It MUST NOT rewrite epistemic ALLOW.
5. HOLD MUST mean CLOSED-with-reason. HOLD MUST NOT enable restricted capability.
6. Implementations MUST NOT interpret UNKNOWN, STALE, CONFLICTING, or UNVERIFIABLE as SATISFIED.

## 2. Identity and authority

Trace: A1, A2, A3, A12, I1, I3

1. High-assurance profiles MUST NOT allow one principal to occupy more than one of `{O, J, U, E}` at the same time.
2. HUMAN_AUTHORITY MAY revoke and force HOLD. HUMAN_AUTHORITY MUST NOT mint C2+ capability tokens.
3. `CAPABILITY_REQUEST` MUST be signed by the requesting agent identity.
4. An observer signature MUST NOT be accepted as capability authorization (`Key_O ⇏ Capability`).
5. An issuer MUST re-evaluate policy predicates. An issuer MUST NOT be a signature oracle for adjudications.

## 3. Evidence

Trace: A17, A20, I6

1. For request `r` and observation window `W_r`:

   `E_req = { o | o.request_id = r ∧ o ∈ W_r }`

2. Missing expected observations MUST be UNVERIFIABLE. They MUST NOT disappear from evaluation.
3. `issuer_proof` MUST be a signature (or threshold reconstruction) over the authorization fields by `K_U` / `K_E`. It MUST NOT be an observer signature.
4. Evidence commitments authenticate integrity, not truth.

## 4. Temporal authority

Trace: A9, A10, A18, A19, A23, I4

1. Activation MUST revalidate `Fresh ∧ ¬Revoked ∧ Scope ∧ PolicyVersion ∧ GatewayState`.
2. Each deployment MUST name its clock source and the behavior on clock failure (fail closed).
3. Renewal MUST be a new authorization evaluation. It MUST NOT continue an expired authorization.
4. Replay of a token across gateways MUST be denied unless a shared replay ledger records the nonce.

## 5. Revocation

Trace: A15, A21, A22

1. The protocol MUST define a `REVOCATION` message class.
2. Revocation MUST NOT depend on the agent presenting a CRL.
3. Deployments MUST publish a maximum acceptance window after revocation is issued.
4. Child / delegated credentials MUST be revoked when the parent is revoked.

## 6. Scope

Trace: A25, A26, A27, I5

1. Scope comparison MUST use a published lattice: exact match, or authorized `id:*` covering `id:leaf`. Unknown identifiers MUST NOT match.
2. Aliases MUST canonicalize before comparison.
3. Widening past `decision_scope` MUST be DENY.
4. Any claim of bounded fault tolerance MUST classify capabilities with C3/C4 as mandatory taxonomy.
5. C4 capabilities MUST NOT be delegated to the agent under ordinary operation.

## 7. Enforcement independence (replaces overbroad I7)

Trace: A4, A10, A13, §27, I7

Protocol invariant (testable):

```
KeyCompromise(O, J, U) ⇏ TokenAcceptance(E)
```

unless a role-valid `K_U`/`K_E` proof and independent health/code-integrity assumptions also hold.

The following remain deployment assumptions, not protocol invariants:

- administrative-root independence
- gateway code integrity
- health attestation of `E` by a party that is not `E`

Threshold cryptography MUST NOT be described as producing those deployment assumptions.

## 8. Containment claim (replaces overbroad I8)

Trace: A29–A32, I8, §36

Empirical claim shape:

```
P(U | F_{A, O≤k}, P, H, N)
```

MUST define:

- `U_token` — unauthorized token issuance
- `U_gateway` — unauthorized gateway activation
- `U_world` — unauthorized effect outside the gateway

`U_token = 0` MUST NOT be reported as `U_world = 0`.

`k`, `N`, and `H` MUST be published with any C6 claim. Observer count `N` MUST NOT be treated as independence `H`.

The protocol MUST NOT claim containment of arbitrary superintelligence.

---

## Frozen invariants after errata

| ID | Text | Class |
|---|---|---|
| I1 | `O ≠ J ≠ U ≠ E ≠ R` | Protocol |
| I2 | UNKNOWN ⇏ ALLOW | Protocol |
| I3 | `Key_O` ⇏ Capability | Protocol |
| I4 | `t > t_expiry` ⇒ DENY | Protocol |
| I5 | Token ⇒ scope-bound under the v0.2 lattice | Protocol |
| I6 | Decision ⇒ evidence commitment | Protocol |
| I7′ | KeyCompromise(O,J,U) ⇏ TokenAcceptance(E) | Protocol, under named key assumptions |
| I8′ | Profile-bound `P(U_gateway \| F_{A,O≤k}, P, H, N)` | Empirical claim |

I7 and I8 from v0.1 are retired as protocol invariants.
