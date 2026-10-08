import Fastify from "fastify";
import { authorizeCapability } from "../gateway/capability-gateway.ts";
import { getCapability } from "../capabilities/registry.ts";
import { publicManifest } from "../plugins/manifest.ts";
import { MemoryReplayStore } from "../auth/replay.ts";
import { MemoryRevocationStore } from "../auth/revocation.ts";
import type { SignedRequestEnvelope } from "../capabilities/types.ts";
import type { CapabilityRequest } from "../auth/capability-request.ts";
import type { VerificationContext } from "../gateway/capability-gateway.ts";

export interface InvokeBody {
  envelope: SignedRequestEnvelope;
  capabilityRequest?: CapabilityRequest;
  requestedScope?: string;
}

// These inputs must come from server-owned stores and policy evaluation,
// never from assertions or verification keys supplied in the HTTP body.
export type AuthorizationInputs = Pick<VerificationContext,
  "resolvedKey" | "issuerRole" | "agentKey" | "policySnapshot" |
  "importedAdjudication" | "delegation" | "deploymentAttestation">;

export interface ServerOptions {
  resolveAuthorization?: (request: InvokeBody) => Promise<AuthorizationInputs | null>;
}

export async function buildServer(options: ServerOptions = {}) {
  const app = Fastify({ logger: false });
  const replayStore = new MemoryReplayStore();
  const revocationStore = new MemoryRevocationStore();

  app.get("/plugin/manifest", async () => publicManifest());
  app.get("/healthz", async () => ({ ok: true, gate: "capability-gateway", protocol: "AGI-CP/0.2" }));
  app.post("/plugin/invoke", async (req, reply) => {
    const incoming = req.body as InvokeBody;
    const body: InvokeBody = {
      envelope: incoming?.envelope,
      capabilityRequest: incoming?.capabilityRequest,
      requestedScope: incoming?.requestedScope,
    };
    if (!body?.envelope) {
      return reply.code(400).send({ decision: "DENY", reason: "AUTHORIZATION_MISSING" });
    }
    let trusted: AuthorizationInputs | null;
    try {
      trusted = await options.resolveAuthorization?.(body) ?? null;
    } catch {
      return reply.code(403).send({ decision: "DENY", reason: "AUTHORIZATION_MISSING" });
    }
    if (!trusted) {
      return reply.code(403).send({ decision: "DENY", reason: "AUTHORIZATION_MISSING" });
    }
    const capability = getCapability(body.envelope.capability);
    const result = await authorizeCapability(
      {
        envelope: body.envelope,
        resolvedKey: trusted.resolvedKey,
        issuerRole: trusted.issuerRole,
        agentKey: trusted.agentKey,
        policySnapshot: trusted.policySnapshot,
        importedAdjudication: trusted.importedAdjudication,
        delegation: trusted.delegation ?? null,
        capabilityRequest: body.capabilityRequest ?? null,
        capability: capability ?? null,
        requestedScope: body.requestedScope,
        deploymentAttestation: trusted.deploymentAttestation ?? null,
      },
      { replayStore, revocationStore },
    );
    const code = result.decision === "ALLOW" ? 200 : result.decision === "INDETERMINATE" ? 202 : 403;
    return reply.code(code).send(result);
  });
  return app;
}

export async function startServer(port = 8787, options: ServerOptions = {}) {
  const app = await buildServer(options);
  await app.listen({ port, host: "0.0.0.0" });
  return app;
}
