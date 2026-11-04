# Evidence window (AGI-CP v0.2 §3.2)

Trace: A17, A20, I6.

For request `r` and observation window `W_r`:

`E_req = { o | o.request_id = r ∧ o ∈ W_r }`

## Rules

1. The required observer set is fixed before evaluation.
2. A missing expected observation is `UNVERIFIABLE`. It stays in the slot list.
3. Implementations MUST NOT delete `UNVERIFIABLE`, `UNKNOWN`, `STALE`, or `CONFLICTING` slots to reach ALLOW.
4. `FAILED` ⇒ DENY. Any non-`SATISFIED` required slot ⇒ not ALLOW (`INDETERMINATE` / `EVIDENCE_UNVERIFIABLE`).
5. Evidence commitments authenticate integrity, not truth.
