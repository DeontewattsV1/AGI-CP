import type { Platform } from "./adapter.ts";

const platforms: Platform[] = ["chatgpt", "claude", "gemini", "perplexity", "copilot", "grok", "deepseek"];

export function supportedPlatforms(): Platform[] {
  return [...platforms];
}
