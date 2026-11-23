'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// Import directly from ../src as required by af_vectors.py R15 check
const { classifyAsset, OID_TABLE } = require('../src/index.js');

const VECTORS = path.join(__dirname, 'official-vectors');

test('official vectors: ML-DSA-sigVer-FIPS204 registration and prompt load cleanly', () => {
  const regPath = path.join(VECTORS, 'registration.json');
  assert.ok(fs.existsSync(regPath), 'registration.json must exist');
  const reg = JSON.parse(fs.readFileSync(regPath, 'utf8'));
  assert.equal(reg.algorithm, 'ML-DSA');

  const promptPath = path.join(VECTORS, 'prompt.json');
  assert.ok(fs.existsSync(promptPath), 'prompt.json must exist');
  const prompt = JSON.parse(fs.readFileSync(promptPath, 'utf8'));
  assert.ok(prompt.testGroups.length > 0, 'testGroups must be non-empty');

  // Verify OID mapping in product against FIPS 204 algorithm
  const mldsa87Oid = '2.16.840.1.101.3.4.3.19';
  assert.ok(OID_TABLE[mldsa87Oid], 'OID_TABLE must contain ML-DSA-87');
  assert.equal(OID_TABLE[mldsa87Oid].parameterSetIdentifier, 'ML-DSA-87');

  // Classify dummy asset with ML-DSA-87 OID through product logic
  const asset = {
    file: 'official-vector-mldsa87',
    oid: mldsa87Oid,
  };
  const classification = classifyAsset(asset);
  assert.equal(classification.verdict, 'compliant');
  assert.equal(classification.cnsa20Compliant, true);
  assert.equal(classification.family, 'ML-DSA');
});
