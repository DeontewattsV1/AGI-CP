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

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string" && item.length > 0);
}

export function isRuntimePassport(value: unknown): value is RuntimePassport {
  if (!value || typeof value !== "object") return false;
  const p = value as Record<string, unknown>;
  const delegation = p.delegation as Record<string, unknown> | undefined;
  const network = p.network as Record<string, unknown> | undefined;
  return p.tract_version === "0.1"
    && typeof p.subject === "string" && p.subject.length > 0
    && (p.parent === undefined || p.parent === null || typeof p.parent === "string")
    && typeof p.purpose === "string" && p.purpose.length > 0
    && isStringArray(p.capabilities)
    && (p.prohibited === undefined || isStringArray(p.prohibited))
    && isStringArray(p.resources)
    && !!delegation
    && typeof delegation.allowed === "boolean"
    && Number.isInteger(delegation.maximum_depth) && Number(delegation.maximum_depth) >= 0
    && Number.isInteger(delegation.maximum_children) && Number(delegation.maximum_children) >= 0
    && !!network
    && (network.default === "deny" || network.default === "allow")
    && isStringArray(network.allow)
    && typeof p.issued_at === "string"
    && typeof p.expires_at === "string"
    && typeof p.nonce === "string" && p.nonce.length >= 8
    && typeof p.issuer === "string" && p.issuer.length > 0
    && typeof p.signature === "string" && p.signature.length > 0;
}

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

/** Verify a short-lived Agent Passport using only an Ed25519 public key. */
export function verifyPassport(input: unknown, publicKeyPem: string, now = Date.now()): PassportVerification {
  if (!isRuntimePassport(input)) return { valid: false, reason: "PASSPORT_SCHEMA_INVALID" };
  if (!Number.isFinite(now)) return { valid: false, reason: "VERIFICATION_CLOCK_INVALID" };
  const passport = input;
  const issued = Date.parse(passport.issued_at);
  const expires = Date.parse(passport.expires_at);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > expires) return { valid: false, reason: "INVALID_TIME_WINDOW" };
  if (now < issued || now >= expires) return { valid: false, reason: "PASSPORT_EXPIRED_OR_NOT_YET_VALID" };
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return { valid: false, reason: "PASSPORT_KEY_TYPE_INVALID" };
    const signature = Buffer.from(passport.signature, "base64url");
    if (!verify(null, passportPayload(passport), key, signature)) return { valid: false, reason: "PASSPORT_SIGNATURE_INVALID" };
    return { valid: true, passport };
  } catch {
    return { valid: false, reason: "PASSPORT_KEY_OR_SIGNATURE_INVALID" };
  }
}
