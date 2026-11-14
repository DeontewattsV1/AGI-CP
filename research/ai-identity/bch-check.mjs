// Copyright (c) 2026 Deonté O'dell Watts. MIT SPDX-License-Identifier: MIT
// Research-only exact BCH coset counting and illustrative IID bit-error tail.
// Not a BCH encoder, decoder, PUF characterization, or security proof.
export function bchDimension(m, t) {
  if (!Number.isInteger(m) || m < 2 || m > 20 || !Number.isInteger(t) || t < 1) {
    throw new RangeError('Require integer m in [2,20] and positive integer t');
  }
  const n = 2 ** m - 1;
  if (2 * t >= n) throw new RangeError('Require 2*t < 2^m - 1');
  const seen = new Set();
  const cosets = [];
  for (let root = 1; root <= 2 * t; root++) {
    if (seen.has(root)) continue;
    const members = [];
    let exponent = root;
    do {
      seen.add(exponent);
      members.push(exponent);
      exponent = (2 * exponent) % n;
    } while (exponent !== root);
    cosets.push(members);
  }
  return {
    m, t, n, roots: 2 * t, cosets: cosets.length,
    generatorDegree: seen.size,
    dimension: n - seen.size,
  };
}

export function iidUncorrectableProbability(n, t, bitErrorRate) {
  if (!Number.isInteger(n) || !Number.isInteger(t) || n < 1 || t < 0 || t >= n ||
      typeof bitErrorRate !== 'number' || bitErrorRate < 0 || bitErrorRate > 1) {
    throw new RangeError('Bad binomial tail parameters');
  }
  if (bitErrorRate === 0) return 0;
  if (bitErrorRate === 1) return 1;
  const firstK = t + 1;
  let logChoose = 0;
  for (let j = 1; j <= firstK; j++) {
    logChoose += Math.log(n - j + 1) - Math.log(j);
  }
  let term = Math.exp(logChoose + firstK * Math.log(bitErrorRate) +
                      (n - firstK) * Math.log1p(-bitErrorRate));
  let total = term;
  for (let k = firstK + 1; k <= n; k++) {
    term *= ((n - k + 1) / k) * (bitErrorRate / (1 - bitErrorRate));
    total += term;
  }
  return Math.min(1, Math.max(0, total));
}

if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1]).href) {
  const parameters = bchDimension(11, 128);
  console.log(JSON.stringify({
    description: 'Primitive narrow-sense binary BCH from roots alpha^1..alpha^256',
    ...parameters,
    veniceClaimedDimension: 639,
    claimedDimensionMatches: parameters.dimension === 639,
    iidAssumption: '2047 independent bit flips with fixed p=0.05 (NOT observed PUF data)',
    illustrativeUncorrectableProbability: iidUncorrectableProbability(2047, 128, 0.05),
    securityAssessed: false,
  }, null, 2));
}
