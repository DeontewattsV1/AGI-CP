import { createPublicKey, verify } from "node:crypto";

export interface RuntimePassport {
  tract_version: "0.1";
  subject: string;
  parent?: string | null;
  purpose: string;
  capabilities: string[];
  prohibited?: string[];
  resources: string[];
  delegation: { allowed: boolean; maximum_depth: number; maximum_children: number };
  network: { default: "deny" | "allow"; allow: string[] };
  issued_at: string;
  expires_at: string;
  nonce: string;
  issuer: string;
  signature: string;
}

export type PassportVerification =
  | { valid: true; passport: RuntimePassport }
  | { valid: false; reason: string };

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().filter((key) => object[key] !== undefined).map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
}

export function passportPayload(passport: RuntimePassport): Buffer {
  const { signature: _signature, ...unsigned } = passport;
  return Buffer.from(canonical(unsigned), "utf8");
}

/** Verify a short-lived Agent Passport using an Ed25519 public key. */
export function verifyPassport(passport: RuntimePassport, publicKeyPem: string, now = Date.now()): PassportVerification {
  const issued = Date.parse(passport.issued_at);
  const expires = Date.parse(passport.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > expires) return { valid: false, reason: "INVALID_TIME_WINDOW" };
  if (now < issued || now >= expires) return { valid: false, reason: "PASSPORT_EXPIRED_OR_NOT_YET_VALID" };
  if (!passport.subject || !passport.issuer || passport.nonce.length < 8) return { valid: false, reason: "PASSPORT_IDENTITY_INVALID" };
  try {
    const key = createPublicKey(publicKeyPem);
    const signature = Buffer.from(passport.signature, "base64url");
    if (!verify(null, passportPayload(passport), key, signature)) return { valid: false, reason: "PASSPORT_SIGNATURE_INVALID" };
    return { valid: true, passport };
  } catch {
    return { valid: false, reason: "PASSPORT_KEY_OR_SIGNATURE_INVALID" };
  }
}
