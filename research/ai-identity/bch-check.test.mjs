// Copyright (c) 2026 Deonté O'dell Watts. MIT SPDX-License-Identifier: MIT
import test from 'node:test';
import assert from 'node:assert/strict';
import { bchDimension, iidUncorrectableProbability } from './bch-check.mjs';

test('primitive narrow-sense BCH(2047,t=128) has degree 1232 and dimension 815', () => {
  assert.deepEqual(bchDimension(11, 128), {
    m: 11, t: 128, n: 2047, roots: 256, cosets: 112,
    generatorDegree: 1232, dimension: 815,
  });
});

test('Venice dimension 639 fails the specified root-set consistency check', () => {
  assert.notEqual(bchDimension(11, 128).dimension, 639);
});

test('small BCH example m=3,t=1 has [7,4] code', () => {
  assert.equal(bchDimension(3, 1).dimension, 4);
});

test('illustrative IID bit-error tail at p=0.05 is about 0.005089565', () => {
  assert.ok(Math.abs(iidUncorrectableProbability(2047, 128, 0.05) -
                     0.005089565232608109) < 1e-9);
});

test('boundary error probabilities and invalid parameters', () => {
  assert.equal(iidUncorrectableProbability(100, 10, 0), 0);
  assert.equal(iidUncorrectableProbability(100, 10, 1), 1);
  assert.throws(() => bchDimension(11, 2047), RangeError);
  assert.throws(() => iidUncorrectableProbability(10, 9, -0.1), RangeError);
});
