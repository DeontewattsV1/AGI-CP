import type { InterceptRequest, InterceptResult, InterceptSurface, RuntimeInterceptor } from "./types.ts";

export interface SurfacePolicy {
  allowedOperations: ReadonlySet<string>;
  allowedCapabilities: ReadonlySet<string>;
  allowedResources?: (resource: string) => boolean;
  baseRisk?: number;
}

export class PolicyInterceptor implements RuntimeInterceptor {
  constructor(readonly surface: InterceptSurface, private readonly policy: SurfacePolicy) {}

  async inspect(request: InterceptRequest): Promise<InterceptResult> {
    if (request.surface !== this.surface) return { decision: "HOLD", reason: "SURFACE_MISMATCH", risk: 1, requiredReceipt: true };
    const auth = request.authorization;
    if (!auth.passportVerified) return { decision: "DENY", reason: "PASSPORT_NOT_VERIFIED", risk: 1, requiredReceipt: true };
    if (auth.gatewayDecision !== "ALLOW") return { decision: "DENY", reason: "GATEWAY_NOT_ALLOW", risk: 1, requiredReceipt: true };
    if (auth.authorizedSubject !== request.agentId) return { decision: "DENY", reason: "SUBJECT_MISMATCH", risk: 1, requiredReceipt: true };
    if (auth.authorizedCapability !== request.capability) return { decision: "DENY", reason: "CAPABILITY_EVIDENCE_MISMATCH", risk: 1, requiredReceipt: true };
    if (!this.policy.allowedCapabilities.has(request.capability)) return { decision: "DENY", reason: "CAPABILITY_NOT_AUTHORIZED_FOR_SURFACE", risk: 0.9, requiredReceipt: true };
    if (!this.policy.allowedOperations.has(request.operation)) return { decision: "DENY", reason: "OPERATION_NOT_AUTHORIZED", risk: 0.8, requiredReceipt: true };
    if (this.policy.allowedResources && !this.policy.allowedResources(request.resource)) return { decision: "DENY", reason: "RESOURCE_NOT_AUTHORIZED", risk: 0.8, requiredReceipt: true };
    return { decision: "ALLOW", reason: "SURFACE_POLICY_ALLOW", risk: this.policy.baseRisk ?? 0, requiredReceipt: true };
  }
}

export function gitInterceptor(allowedRepos: ReadonlySet<string>): RuntimeInterceptor {
  return new PolicyInterceptor("git", {
    allowedOperations: new Set(["read", "diff", "status", "commit", "push", "create_pr"]),
    allowedCapabilities: new Set(["repo.read", "git.write", "repo.create_pr"]),
    allowedResources: (resource) => allowedRepos.has(resource),
  });
}

export function shellInterceptor(allowedCommands: ReadonlySet<string>): RuntimeInterceptor {
  return new PolicyInterceptor("shell", {
    allowedOperations: allowedCommands,
    allowedCapabilities: new Set(["shell.exec"]),
    baseRisk: 0.2,
  });
}

export function httpInterceptor(allowedOrigins: ReadonlySet<string>): RuntimeInterceptor {
  return new PolicyInterceptor("http", {
    allowedOperations: new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]),
    allowedCapabilities: new Set(["http.request"]),
    allowedResources: (resource) => {
      try { return allowedOrigins.has(new URL(resource).origin); } catch { return false; }
    },
    baseRisk: 0.1,
  });
}

export function mcpInterceptor(allowedTools: ReadonlySet<string>): RuntimeInterceptor {
  return new PolicyInterceptor("mcp", {
    allowedOperations: new Set(["call"]),
    allowedCapabilities: new Set(["mcp.tool"]),
    allowedResources: (resource) => allowedTools.has(resource),
    baseRisk: 0.1,
  });
}
