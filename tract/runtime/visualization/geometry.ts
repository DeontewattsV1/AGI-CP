export type RuntimeState = "NORMAL" | "OBSERVE" | "RESTRICT" | "QUARANTINE" | "TERMINATE";

export interface GeometryPoint {
  x: number;
  y: number;
  z: number;
}

export interface ObservableAgent {
  id: string;
  parentId?: string;
  state: RuntimeState;
  risk: number;
  capabilityCount: number;
  receiptCount: number;
  position: GeometryPoint;
}

export interface MosaicCell {
  receiptHash: string;
  agentId: string;
  state: RuntimeState;
  risk: number;
  changed: boolean;
}

/**
 * Visual semantics only. Geometry never grants authority.
 * Pyramid depth communicates delegation depth; radius communicates risk.
 */
export function monumentalPosition(index: number, depth: number, risk: number): GeometryPoint {
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  const theta = index * goldenAngle;
  const layerRadius = Math.max(0.15, 1 - depth * 0.14);
  const riskExpansion = 1 + Math.min(1, Math.max(0, risk)) * 0.35;
  const radius = layerRadius * riskExpansion;
  return {
    x: Math.cos(theta) * radius,
    y: 1 - depth * 0.24,
    z: Math.sin(theta) * radius,
  };
}

export function riskToState(risk: number): RuntimeState {
  if (risk >= 0.85) return "TERMINATE";
  if (risk >= 0.70) return "QUARANTINE";
  if (risk >= 0.50) return "RESTRICT";
  if (risk >= 0.25) return "OBSERVE";
  return "NORMAL";
}

export function fieldEnergy(agents: ObservableAgent[]): number {
  if (agents.length === 0) return 0;
  const sum = agents.reduce((acc, agent) => acc + agent.risk * (1 + agent.capabilityCount / 10), 0);
  return sum / agents.length;
}

export function anomalyGradient(previous: number, current: number, dtSeconds: number): number {
  if (dtSeconds <= 0) return 0;
  return (current - previous) / dtSeconds;
}

export function shouldPulseInjection(previousRisk: number, currentRisk: number, threshold = 0.15): boolean {
  return currentRisk - previousRisk >= threshold || riskToState(previousRisk) !== riskToState(currentRisk);
}
