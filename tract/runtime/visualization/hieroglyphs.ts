import type { RuntimeState } from "./geometry.ts";

export type HieroglyphKey =
  | "identity"
  | "observe"
  | "authorize"
  | "delegate"
  | "receipt"
  | "warning"
  | "revoke"
  | "quarantine"
  | "proof";

/**
 * Semantic glyph vocabulary for the UI. Glyphs are redundant visual labels,
 * never security decisions. Text/ARIA labels MUST accompany them.
 */
export const HIEROGLYPHS: Record<HieroglyphKey, string> = {
  identity: "𓂀",
  observe: "𓁹",
  authorize: "𓋹",
  delegate: "𓂧",
  receipt: "𓏞",
  warning: "𓆣",
  revoke: "𓌻",
  quarantine: "𓊃",
  proof: "𓍿",
};

export function stateGlyph(state: RuntimeState): string {
  switch (state) {
    case "NORMAL": return HIEROGLYPHS.authorize;
    case "OBSERVE": return HIEROGLYPHS.observe;
    case "RESTRICT": return HIEROGLYPHS.warning;
    case "QUARANTINE": return HIEROGLYPHS.quarantine;
    case "TERMINATE": return HIEROGLYPHS.revoke;
  }
}
