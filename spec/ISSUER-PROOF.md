# issuer_proof (AGI-CP v0.2 §3.3)

`issuer_proof` MUST be a signature over the authorization fields by `K_U` or `K_E`.
It MUST NOT be an observer signature.

```
IssuerProof {
  requestId
  subject
  capability
  signerRole = ISSUER | ENFORCER
  signature
}
```

Envelope HMAC is not a substitute for this proof.
Key_O ⇏ issuer_proof.
