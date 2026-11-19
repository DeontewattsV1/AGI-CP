# CAPABILITY_REQUEST (AGI-CP v0.2 §2.3)

Trace: A1, A2, A12, I3.

`CAPABILITY_REQUEST` MUST be signed by the requesting agent identity.

```
CAPABILITY_REQUEST {
  protocol_version: "0.2.0"
  message_type: "CAPABILITY_REQUEST"
  request_id
  subject            // agent identity
  capability
  scope?
  timestamp
  nonce
  signer_role = AGENT
  signature          // over the unsigned fields, by the agent key
}
```

## Rules

1. The issuer envelope signature is not a substitute for the agent request signature.
2. `signer_role` MUST be `AGENT`. Observer signatures MUST NOT satisfy this MUST.
3. `subject` MUST equal the envelope subject.
4. `capability` MUST equal the envelope capability.
5. HUMAN_AUTHORITY MUST NOT mint C2+ tokens by signing a `CAPABILITY_REQUEST` as the agent.
