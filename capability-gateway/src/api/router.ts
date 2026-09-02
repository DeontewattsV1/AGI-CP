import Fastify from "fastify";
import { authorizeCapability } from "../gateway/capability-gateway.ts";
import { getCapability } from "../capabilities/registry.ts";
import { publicManifest } from "../plugins/manifest.ts";
import { MemoryReplayStore } from "../auth/replay.ts";
import { MemoryRevocationStore } from "../auth/revocation.ts";
import type { DeploymentAttestation, SignedRequestEnvelope } from "../capabilities/types.ts";

export interface InvokeBody {
  envelope: SignedRequestEnvelope;
  resolvedKey?: string;
  issuerRole?: "AGENT" | "OBSERVER" | "JUDGE" | "ISSUER" | "ENFORCER" | "RECORDER" | "HUMAN_AUTHORITY";
  requestedScope?: string;
  deploymentAttestation?: DeploymentAttestation;
  delegation?: {
    id: string;
    issuer: string;
    subject: string;
    capabilities: string[];
    scopes: string[];
    issuedAt: number;
    expiresAt: number;
    revoked: boolean;
    parentId?: string;
  };
}

export async function buildServer() {
  const app = Fastify({ logger: false });
  const replayStore = new MemoryReplayStore();
  const revocationStore = new MemoryRevocationStore();

  app.get("/plugin/manifest", async () => publicManifest());
  app.get("/healthz", async () => ({ ok: true, gate: "capability-gateway", protocol: "AGI-CP/0.2" }));
  app.post("/plugin/invoke", async (req, reply) => {
    const body = req.body as InvokeBody;
    if (!body?.envelope) {
      return reply.code(400).send({ decision: "DENY", reason: "AUTHORIZATION_MISSING" });
    }
    const capability = getCapability(body.envelope.capability);
    const result = await authorizeCapability(
      {
        envelope: body.envelope,
        resolvedKey: body.resolvedKey,
        issuerRole: body.issuerRole,
        delegation: body.delegation ?? null,
        capability: capability ?? null,
        requestedScope: body.requestedScope,
        deploymentAttestation: body.deploymentAttestation ?? null,
      },
      { replayStore, revocationStore },
    );
    const code = result.decision === "ALLOW" ? 200 : result.decision === "INDETERMINATE" ? 202 : 403;
    return reply.code(code).send(result);
  });
  return app;
}

export async function startServer(port = 8787) {
  const app = await buildServer();
  await app.listen({ port, host: "0.0.0.0" });
  return app;
}
