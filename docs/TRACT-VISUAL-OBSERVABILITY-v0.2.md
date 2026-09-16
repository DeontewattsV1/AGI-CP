# TRACT v0.2 — Monumental Observability Geometry

Status: visual/runtime design contract. Visualization is an observer, never an authority source.

## Design thesis

TRACT should make a security-state change visible before an operator has to read a log line. The visual grammar combines monumental geometry, hieroglyphic semantic markers, micro-mosaic event density, and physics-inspired field representations.

The Egyptian visual language is used as an information architecture, not as a claim that historical hieroglyphs encoded modern computing concepts.

## Three visual scales

### 1. Monumental scale — lineage pyramid

The largest geometry represents authority topology.

- apex: human or organization root authority;
- descending tiers: orchestrators, agents, micro-agents, tools;
- edge: delegated authority;
- severed edge: revocation;
- expanding halo: rising risk;
- missing/occluded node: unverifiable telemetry and therefore closed state.

The pyramid is intentionally stable under normal operation. Sudden topology changes become pre-attentively visible.

### 2. Glyph scale — semantic state

Each node carries a redundant glyph plus text label. Glyphs MUST NOT be the only accessibility channel.

Suggested vocabulary:

- Eye: observation/telemetry;
- Ankh: valid bounded authority;
- scarab: anomaly/warning;
- papyrus/record mark: receipt/evidence;
- broken/severed mark: revocation;
- enclosure: quarantine.

### 3. Micro scale — receipt mosaic

Every signed Event Receipt becomes one mosaic cell. A trace becomes a strip; an agent session becomes a panel; a deployment becomes a wall.

A cell encodes at minimum:

`{ agent, capability, decision, risk-band, receipt-hash-prefix, temporal-order }`

The mosaic is derived from receipts and MUST be reproducible from the ledger. It is not an independent source of truth.

## Physics-inspired observability

Physics is used as a visualization model, not as evidence that agent behavior literally obeys physical field laws.

For agent i define a visual risk mass:

`m_i = r_i * (1 + c_i / 10)`

where `r_i` is normalized risk and `c_i` is active capability count.

A system field-energy summary is:

`E = (1/N) * Σ m_i`

A rapid behavioral transition is represented by the temporal gradient:

`G = ΔE / Δt`

Large positive G produces an injection pulse even when absolute E has not yet reached quarantine. This makes fast changes visible.

A visual interaction field MAY be rendered as:

`F(x) = Σ_i m_i / (||x - x_i||² + ε)`

This is explicitly a display transform. It MUST NOT independently authorize, deny, accuse, or classify an agent.

## Injection / response visibility

A response pulse is triggered visually when either:

`risk(t) - risk(t-1) >= δ`

or the deterministic risk band changes.

The operator sees the pulse propagate from the changed mosaic cell → agent node → lineage edge → affected descendants. The runtime response itself remains controlled by deterministic TRACT/AGI-CP policy.

## Required live views

1. **Lineage Monument** — root-to-tool delegation topology.
2. **Receipt Mosaic** — every real Event Receipt in temporal order.
3. **Revocation Fracture** — descendants visibly detach when a parent is revoked.
4. **Risk Field** — physics-inspired topology of aggregate behavioral pressure.
5. **Capability Constellation** — capabilities around each principal, showing permitted versus prohibited boundaries.
6. **Injection Pulse** — immediate visible propagation of policy/guardrail/revocation changes.
7. **Proof Lens** — select any glyph/cell/node and reveal the underlying signed receipt, policy decision, hashes, and lineage.

## Live data contract

The visualization consumes only normalized runtime events:

```ts
interface TractVisualEvent {
  eventId: string;
  traceId: string;
  agentId: string;
  parentAgentId?: string;
  capability: string;
  decision: "ALLOW" | "DENY" | "INDETERMINATE";
  risk: number;
  state: "NORMAL" | "OBSERVE" | "RESTRICT" | "QUARANTINE" | "TERMINATE";
  previousEventHash: string;
  eventHash: string;
  timestamp: string;
}
```

No simulated node may be displayed as a live principal. Demo/synthetic events MUST be visibly labeled as synthetic.

## p5.js rendering contract

The p5.js client should render from a read-only event stream. It MUST NOT hold issuer keys, raw provider credentials, gateway mutation credentials, or revocation authority.

Recommended render pipeline:

`Event Receipt -> verify/read model -> visual event -> topology update -> mosaic cell -> field recompute -> frame`

Operator buttons such as REVOKE or QUARANTINE must call a separately authenticated control API and display the resulting signed response receipt. The canvas itself never mutates authority.

## Accessibility and operator safety

Color is redundant. Every state uses geometry + glyph + text + motion pattern. Reduced-motion mode replaces pulses with border/shape changes. Every visual anomaly must be inspectable as structured text. Hieroglyphic marks are mnemonic symbols, not substitutes for precise security terminology.
