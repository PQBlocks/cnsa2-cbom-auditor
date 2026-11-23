'use strict';

// S-12 — JWK / JWKS input.
// Contract (spec/spec.md S-12): lib/jwk.js — parseJwk(json) -> Asset;
// known kty → family; unknown → unknown + raw kty.
// Test: JWK fixtures for RSA/EC/EdDSA/OKP; unregistered alg → unknown.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const LANE = path.join(__dirname, '..');
const JWK = require(path.join(LANE, 'lib', 'jwk'));

const fixtures = {
  rsaPublic: {
    kty: 'RSA',
    alg: 'RS256',
    n: '0x',
    e: 'AQAB',
  },
  rsaPrivate: {
    kty: 'RSA',
    alg: 'RS256',
    n: '0x',
    e: 'AQAB',
    d: '0x',
    p: '0x',
    q: '0x',
    dp: '0x',
    dq: '0x',
    qi: '0x',
  },
  ecPublic: {
    kty: 'EC',
    alg: 'ES256',
    crv: 'P-256',
    x: '0x',
    y: '0x',
  },
  ecPrivate: {
    kty: 'EC',
    alg: 'ES256',
    crv: 'P-256',
    d: '0x',
    x: '0x',
    y: '0x',
  },
  okpPublic: {
    kty: 'OKP',
    alg: 'EdDSA',
    crv: 'Ed25519',
    x: '0x',
  },
  okpPrivate: {
    kty: 'OKP',
    alg: 'EdDSA',
    crv: 'Ed25519',
    d: '0x',
    x: '0x',
  },
  symmetric: {
    kty: 'SYMMETRIC',
    alg: 'A128K',
    k: '0x',
  },
  unknownKty: {
    kty: 'UNKNOWN',
  },
  unknownAlg: {
    kty: 'RSA',
    alg: 'UNKNOWN-ALG',
  },
};

test('parseJwk maps RSA kty to family rsa', () => {
  const result = JWK.parseJwk(fixtures.rsaPublic);
  assert.equal(result.type, 'rsa');
  assert.equal(result.kty, 'RSA');
});

test('parseJwk maps RSA private kty to family rsa', () => {
  const result = JWK.parseJwk(fixtures.rsaPrivate);
  assert.equal(result.type, 'rsa');
  assert.equal(result.kty, 'RSA');
});

test('parseJwk maps EC kty to family ec', () => {
  const result = JWK.parseJwk(fixtures.ecPublic);
  assert.equal(result.type, 'ec');
  assert.equal(result.kty, 'EC');
  assert.equal(result.crv, 'P-256');
});

test('parseJwk maps EC private kty to family ec', () => {
  const result = JWK.parseJwk(fixtures.ecPrivate);
  assert.equal(result.type, 'ec');
  assert.equal(result.kty, 'EC');
});

test('parseJwk maps OKP kty to family okp', () => {
  const result = JWK.parseJwk(fixtures.okpPublic);
  assert.equal(result.type, 'okp');
  assert.equal(result.kty, 'OKP');
  assert.equal(result.crv, 'Ed25519');
});

test('parseJwk maps OKP private kty to family okp', () => {
  const result = JWK.parseJwk(fixtures.okpPrivate);
  assert.equal(result.type, 'okp');
  assert.equal(result.kty, 'OKP');
});

test('parseJwk maps SYMMETRIC kty to family symmetric', () => {
  const result = JWK.parseJwk(fixtures.symmetric);
  assert.equal(result.type, 'symmetric');
  assert.equal(result.kty, 'SYMMETRIC');
});

test('parseJwk returns unknown for unregistered kty', () => {
  const result = JWK.parseJwk(fixtures.unknownKty);
  assert.equal(result.type, 'unknown');
  assert.equal(result.kty, 'UNKNOWN');
});

test('parseJwk handles unregistered alg with known kty', () => {
  const result = JWK.parseJwk(fixtures.unknownAlg);
  assert.equal(result.type, 'rsa');
  assert.equal(result.kty, 'RSA');
  assert.equal(result.alg, 'UNKNOWN-ALG');
});

test('parseJwk throws on non-object input', () => {
  assert.throws(() => JWK.parseJwk(null), TypeError);
  assert.throws(() => JWK.parseJwk('not an object'), TypeError);
  assert.throws(() => JWK.parseJwk(42), TypeError);
});

test('parseJwk throws on input without kty', () => {
  assert.throws(() => JWK.parseJwk({}), TypeError);
});
