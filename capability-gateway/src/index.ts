export { authorizeCapability } from "./gateway/capability-gateway.ts";
export { signEnvelope, verifySignature } from "./auth/signature.ts";
export { MemoryReplayStore } from "./auth/replay.ts";
export { MemoryRevocationStore } from "./auth/revocation.ts";
export { getCapability, listCapabilities } from "./capabilities/registry.ts";
export { publicManifest } from "./plugins/manifest.ts";
export { buildServer, startServer } from "./api/router.ts";
export { combineDecisions } from "./capabilities/policy.ts";

import { startServer } from "./api/router.ts";

const run = process.argv[1]?.includes("index");
if (run && process.env.AGICP_START === "1") {
  startServer().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
