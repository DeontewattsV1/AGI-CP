export type InterceptSurface = "git" | "shell" | "http" | "mcp";
export type InterceptDecision = "ALLOW" | "DENY" | "HOLD";

export interface AuthorizationEvidence {
  passportVerified: boolean;
  gatewayDecision: "ALLOW" | "DENY" | "INDETERMINATE";
  authorizedSubject: string;
  authorizedCapability: string;
}

export interface InterceptRequest {
  surface: InterceptSurface;
  agentId: string;
  parentAgentId?: string;
  passportId: string;
  capability: string;
  resource: string;
  operation: string;
  argumentsDigest: string;
  timestamp: string;
  authorization: AuthorizationEvidence;
}

export interface InterceptResult {
  decision: InterceptDecision;
  reason: string;
  risk: number;
  requiredReceipt: true;
}

export interface RuntimeInterceptor {
  readonly surface: InterceptSurface;
  inspect(request: InterceptRequest): Promise<InterceptResult>;
}

/** Fail closed: every matching interceptor must explicitly allow. */
export async function inspectAll(
  request: InterceptRequest,
  interceptors: RuntimeInterceptor[],
): Promise<InterceptResult> {
  const matching = interceptors.filter((i) => i.surface === request.surface);
  if (matching.length === 0) {
    return { decision: "HOLD", reason: "INTERCEPTOR_MISSING", risk: 1, requiredReceipt: true };
  }

  let maxRisk = 0;
  for (const interceptor of matching) {
    const result = await interceptor.inspect(request);
    maxRisk = Math.max(maxRisk, result.risk);
    if (result.decision === "DENY") return { ...result, risk: maxRisk };
    if (result.decision === "HOLD") return { ...result, risk: maxRisk };
  }
  return { decision: "ALLOW", reason: "ALL_INTERCEPTORS_ALLOW", risk: maxRisk, requiredReceipt: true };
}
