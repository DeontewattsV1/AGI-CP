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

### HTTP authorization configuration

`buildServer({ resolveAuthorization })` (or `startServer(port, options)`) requires
an application-provided, trusted authorization resolver for `/plugin/invoke`.
Without it, invocation fails closed with `403 AUTHORIZATION_MISSING`; health
and manifest endpoints remain available. The default CLI does not configure a
resolver and cannot authorize invocations.

The HTTP body supplies only `envelope`, `capabilityRequest`, and
`requestedScope`. The resolver must look up issuer/agent keys, issuer role,
delegation, and deployment attestation in trusted server-owned stores, and
supply a current issuer policy evaluation and any verified imported adjudication.
It must bind those records to the submitted identities, capability, scope, and
delegation ID. Request data is untrusted: do not construct an approving policy
snapshot from client assertions. Resolver exceptions deny without returning
backend details. Legacy body fields for keys or policy are ignored.

This adapter is a reference integration boundary, not a production credential
store or a claim of complete protocol security. Production trust-store and
policy-evaluator integration remains deployment-specific.

## Claim hierarchy

Protocol invariant ⊂ reference implementation property ⊂ deployment assumption ⊂ empirical security claim.

A passing test suite is the second layer only.

## License

MIT
