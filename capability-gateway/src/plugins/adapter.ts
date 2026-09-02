import type { SignedRequestEnvelope } from "../capabilities/types.ts";

export type Platform = "chatgpt" | "claude" | "gemini" | "perplexity" | "copilot" | "grok" | "deepseek";

export function toEnvelope(
  platform: Platform,
  input: {
    requestId: string;
    timestamp: number;
    issuer: string;
    subject: string;
    capability: string;
    delegationId: string;
    nonce: string;
    payload: unknown;
    signature: string;
  },
): SignedRequestEnvelope {
  void platform;
  return { ...input };
}
