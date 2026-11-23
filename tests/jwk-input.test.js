'use strict';

// S-12 — JWK / JWKS input (second test file).
// Contract (spec/spec.md S-12): lib/jwk.js — parseJwk(json) -> Asset;
// known kty → family; unknown → unknown + raw kty.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const LANE = path.join(__dirname, '..');
const JWK = require(path.join(LANE, 'lib', 'jwk'));

test('parseJwk returns unknown with raw kty for unregistered kty EC variant', () => {
  const result = JWK.parseJwk({ kty: 'EC-X9', crv: 'P-384' });
  assert.strictEqual(result.type, 'unknown');
  assert.strictEqual(result.kty, 'EC-X9');
});

test('parseJwk returns unknown with raw kty for empty string kty', () => {
  const result = JWK.parseJwk({ kty: '' });
  assert.strictEqual(result.type, 'unknown');
  assert.strictEqual(result.kty, '');
});

test('parseJwk preserves alg for known kty with unusual alg', () => {
  const result = JWK.parseJwk({ kty: 'OKP', alg: 'Ed25519ph', crv: 'Ed25519', x: '0x' });
  assert.strictEqual(result.type, 'okp');
  assert.strictEqual(result.alg, 'Ed25519ph');
});
