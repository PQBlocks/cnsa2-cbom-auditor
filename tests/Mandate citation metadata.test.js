'use strict';
// S-15 — Mandate citation metadata
// Contract: lib/metadata.js injects metadata.properties:
//   cnsa2:mandate      (PP-22-1338)
//   nist:transition    (IR 8547 Oct 2026)
//   classification:oracle (OpenSSL 3.6.5)
// Test: CBOM carries all three properties with correct values.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const LANE = path.dirname(__dirname);

function loadExpectedCbom() {
  return JSON.parse(fs.readFileSync(path.join(LANE, 'golden-vectors', 'expected', 'sample-cbom.json'), 'utf8'));
}

test('exports injectMetadata and getMandateProperties', () => {
  const metadata = require('../lib/metadata.js');
  assert.equal(typeof metadata.injectMetadata, 'function');
  assert.equal(typeof metadata.getMandateProperties, 'function');
});

test('getMandateProperties returns three properties with correct names and values', () => {
  const { getMandateProperties } = require('../lib/metadata.js');
  const props = getMandateProperties();
  assert.equal(Array.isArray(props), true);
  assert.equal(props.length, 3);

  const names = props.map(p => p.name).sort();
  assert.deepEqual(names, ['classification:oracle', 'cnsa2:mandate', 'nist:transition']);

  const cnsa2 = props.find(p => p.name === 'cnsa2:mandate');
  const nist = props.find(p => p.name === 'nist:transition');
  const oracle = props.find(p => p.name === 'classification:oracle');

  assert.equal(cnsa2.value, 'PP-22-1338');
  assert.equal(nist.value, 'IR 8547 Oct 2026');
  assert.equal(oracle.value, 'OpenSSL 3.6.5');
});

test('injectMetadata adds all three mandate properties to metadata', () => {
  const { injectMetadata } = require('../lib/metadata.js');
  const metadata = { timestamp: '2026-01-01T00:00:00.000Z', properties: [] };
  const result = injectMetadata(metadata, 'OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026)');

  assert.ok(Array.isArray(result.properties));
  assert.equal(result.properties.length, 3);

  const names = result.properties.map(p => p.name).sort();
  assert.deepEqual(names, ['classification:oracle', 'cnsa2:mandate', 'nist:transition']);

  const cnsa2 = result.properties.find(p => p.name === 'cnsa2:mandate');
  const nist = result.properties.find(p => p.name === 'nist:transition');
  const oracle = result.properties.find(p => p.name === 'classification:oracle');

  assert.equal(cnsa2.value, 'NSA CNSA 2.0 (U/OO/194427-22, SEP 2022 v1.0)');
  assert.equal(nist.value, 'NIST IR 8547 (October 2026) Tables 2 and 4');
  assert.equal(oracle.value, 'OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026)');
});

test('injectMetadata does not duplicate properties on repeated calls', () => {
  const { injectMetadata } = require('../lib/metadata.js');
  let metadata = { timestamp: '2026-01-01T00:00:00.000Z', properties: [] };
  metadata = injectMetadata(metadata, 'OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026)');
  metadata = injectMetadata(metadata, 'OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026)');

  assert.equal(metadata.properties.length, 3);
});

test('generateCbom output carries all three mandate metadata properties matching sample-cbom.json', async () => {
  const { generateCbom } = require('../lib/cbom.js');
  const { parseCert } = require('../lib/x509.js');

  function pemToDer(pemText) {
    const body = pemText.split(/\r?\n/).filter(l => l && !l.startsWith('-----')).join('');
    return Buffer.from(body, 'base64');
  }

  function readPem(relPath) {
    return fs.readFileSync(path.join(LANE, 'golden-vectors', relPath), 'utf8');
  }

  const expectedCbom = loadExpectedCbom();
  const expectedProps = expectedCbom.metadata.properties;

  // Use a single asset to generate a CBOM and verify metadata properties
  const name = expectedCbom.components[0].name; // ec-p256-sha256.crt
  const pem = readPem('certs/' + name);
  const asset = parseCert(pemToDer(pem));
  asset.name = name;
  asset.file = 'certs/' + name;

  const bom = await generateCbom([asset], {
    serialNumber: expectedCbom.serialNumber,
    timestamp: expectedCbom.metadata.timestamp,
    oracle: expectedCbom.metadata.properties.find(p => p.name === 'classification:oracle').value,
  });

  // Verify all three mandate properties are present with correct values
  const props = bom.metadata.properties;
  assert.ok(Array.isArray(props));
  assert.equal(props.length >= 3, true);

  const cnsa2 = props.find(p => p.name === 'cnsa2:mandate');
  const nist = props.find(p => p.name === 'nist:transition');
  const oracle = props.find(p => p.name === 'classification:oracle');

  assert.ok(cnsa2, 'cnsa2:mandate property missing');
  assert.ok(nist, 'nist:transition property missing');
  assert.ok(oracle, 'classification:oracle property missing');

  assert.equal(cnsa2.value, expectedProps.find(p => p.name === 'cnsa2:mandate').value);
  assert.equal(nist.value, expectedProps.find(p => p.name === 'nist:transition').value);
  assert.equal(oracle.value, expectedProps.find(p => p.name === 'classification:oracle').value);
});