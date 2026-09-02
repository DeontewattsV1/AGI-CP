import { listCapabilities } from "../capabilities/registry.ts";

export function publicManifest() {
  return {
    name: "agi-cp-capability-gateway",
    version: "0.2.0",
    protocol: "AGI-CP",
    protocolVersion: "0.2.0",
    discoveryOnly: true as const,
    capabilities: listCapabilities().map((c) => ({
      id: c.id,
      version: c.version,
      risk: c.risk,
      description: c.description,
      scopes: c.scopes,
    })),
  };
}
