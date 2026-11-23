'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { parseSpki } = require('../lib/spki.js');
const { OID_TABLE } = require('../lib/constants.js');
const { readFileSync } = require('node:fs');

const LANE = path.dirname(__dirname);
const GOLDEN_SPKI_DIR = path.join(LANE, 'golden-vectors', 'spki');
const EXPECTED_PATH = path.join(LANE, 'golden-vectors', 'expected', 'expected-classification.json');

const expected = JSON.parse(readFileSync(EXPECTED_PATH, 'utf8'));
const expectedSpki = expected.keys; // array of 12 SPKI key entries

// keys[] carries only the OpenSSL-oracle fields (oid, keyOctets); it has no
// family/paramSet. Those come from certificates[].publicKey — the same interop
// oracle the X.509 test uses — because every golden certificate embeds an SPKI
// that must classify identically. ML-KEM-1024 has no certificate vector (KEM-only
// key), so its oracle is derived from the OID registry, itself transcribed from
// RFC 9935 §3 / FIPS 203 Table 2.
const oracleByBase = new Map();
for (const cert of expected.certificates) {
  const base = cert.file.replace(/^certs\//, '').replace(/\.crt$/, '');
  oracleByBase.set(base, { family: cert.publicKey.family, paramSet: cert.publicKey.paramSet });
}
{
  const mlkem = OID_TABLE['2.16.840.1.101.3.4.4.3'];
  assert.ok(mlkem, 'ML-KEM-1024 OID missing from OID_TABLE');
  oracleByBase.set('mlkem1024', { family: 'ML-KEM', paramSet: mlkem.parameterSetIdentifier });
}

function pemToDer(pemText) {
  const lines = pemText.split(/\r?\n/);
  const body = lines.filter((l) => l && !l.startsWith('-----')).join('');
  return Buffer.from(body, 'base64');
}

test('exports parseSpki', () => {
  assert.equal(typeof parseSpki, 'function');
});

for (const entry of expectedSpki) {
  const file = entry.file.replace(/^spki\//, ''); // e.g. ec-p256-sha256.spki.pem
  const base = file.replace(/\.spki\.pem$/, '');
  const oracle = oracleByBase.get(base);
  assert.ok(oracle, `no family/paramSet oracle for ${base}`);

  test(`parseSpki extracts ${file} (OID, key bytes, family, paramSet)`, () => {
    const pem = readFileSync(path.join(GOLDEN_SPKI_DIR, file), 'utf8');
    const der = pemToDer(pem);
    const asset = parseSpki(der);

    // Shape
    assert.ok(asset, `${file}: parseSpki returned falsy`);
    assert.equal(typeof asset.oid, 'string', `${file}: oid must be string`);
    assert.ok(Buffer.isBuffer(asset.keyBytes), `${file}: keyBytes must be Buffer`);
    assert.ok(asset.family, `${file}: family must be set`);
    assert.equal(asset.oid, entry.oid, `${file}: oid mismatch`);
    assert.equal(asset.keyBytes.length, entry.keyOctets, `${file}: keyBytes length mismatch (got ${asset.keyBytes.length}, expected ${entry.keyOctets})`);
    assert.equal(asset.family, oracle.family, `${file}: family mismatch (got ${asset.family}, expected ${oracle.family})`);
    assert.equal(asset.paramSet, oracle.paramSet, `${file}: paramSet mismatch (got ${asset.paramSet}, expected ${oracle.paramSet})`);
  });
}

test('SPKI expected-classification.json lists exactly 12 keys', () => {
  assert.equal(expectedSpki.length, 12);
});

test('SPKI vectors DER bytes parse without error against all 12 golden vectors', () => {
  for (const entry of expectedSpki) {
    const file = entry.file;
    const cleanFile = file.startsWith('spki/') ? file.slice(5) : file;
    const pem = readFileSync(path.join(GOLDEN_SPKI_DIR, cleanFile), 'utf8');
    const der = pemToDer(pem);
    const asset = parseSpki(der);
    assert.ok(asset, `${file}: parseSpki must not throw`);
  }
});