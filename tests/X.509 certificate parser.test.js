'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, readdirSync } = require('node:fs');
const { join, dirname } = require('node:path');
const { createHash } = require('node:crypto');

const LANE = dirname(__dirname);
const CERTS_DIR = join(LANE, 'golden-vectors', 'certs');
const EXPECTED_PATH = join(LANE, 'golden-vectors', 'expected', 'expected-classification.json');

const { parseCert, InvalidAssetError, DecompressionError } = require('../lib/x509.js');
const { OID_TABLE, CLASSICAL_OIDS, PARAMETER_SETS } = require('../lib/constants.js');

// Helper: PEM -> DER
function pemToDer(pemText) {
  const lines = pemText.split(/\r?\n/);
  const body = lines.filter((l) => l && !l.startsWith('-----')).join('');
  return Buffer.from(body, 'base64');
}

// Helper: OpenSSL date parsing
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
function parseOpenSslDate(s) {
  const m = s.match(/^([A-Za-z]{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4}) GMT$/);
  assert.ok(m, `unparsable OpenSSL date: ${s}`);
  const [, mon, day, hh, mm, ss, yyyy] = m;
  return new Date(Date.UTC(Number(yyyy), MONTHS[mon], Number(day), Number(hh), Number(mm), Number(ss)));
}

// Per-file expectations from golden-vectors/expected/expected-classification.json
const PER_FILE = {
  'ec-p256-sha256.crt':    { sigOid: '1.2.840.10045.4.3.2',  spkiOid: '1.2.840.10045.2.1',  keyBytes: 65 },
  'ec-p384-sha384.crt':    { sigOid: '1.2.840.10045.4.3.3',  spkiOid: '1.2.840.10045.2.1',  keyBytes: 97 },
  'ed25519.crt':           { sigOid: '1.3.101.112',          spkiOid: '1.3.101.112',        keyBytes: 32 },
  'mldsa44.crt':           { sigOid: '2.16.840.1.101.3.4.3.17', spkiOid: '2.16.840.1.101.3.4.3.17', keyBytes: 1312 },
  'mldsa65.crt':           { sigOid: '2.16.840.1.101.3.4.3.18', spkiOid: '2.16.840.1.101.3.4.3.18', keyBytes: 1952 },
  'mldsa87.crt':           { sigOid: '2.16.840.1.101.3.4.3.19', spkiOid: '2.16.840.1.101.3.4.3.19', keyBytes: 2592 },
  'rsa2048-sha256.crt':    { sigOid: '1.2.840.113549.1.1.11', spkiOid: '1.2.840.113549.1.1.1', keyBytes: 270 },
  'rsa3072-sha384.crt':    { sigOid: '1.2.840.113549.1.1.12', spkiOid: '1.2.840.113549.1.1.1', keyBytes: 398 },
  'rsa4096-sha512.crt':    { sigOid: '1.2.840.113549.1.1.13', spkiOid: '1.2.840.113549.1.1.1', keyBytes: 526 },
  'slhdsa-sha2-128s.crt':  { sigOid: '2.16.840.1.101.3.4.3.20', spkiOid: '2.16.840.1.101.3.4.3.20', keyBytes: 32 },
  'slhdsa-shake-256f.crt': { sigOid: '2.16.840.1.101.3.4.3.31', spkiOid: '2.16.840.1.101.3.4.3.31', keyBytes: 64 },
};

const expected = JSON.parse(readFileSync(EXPECTED_PATH, 'utf8'));
const expectedByFile = new Map(expected.certificates.map((c) => [c.file.replace(/^certs\//, ''), c]));

function certBytes(file) {
  return pemToDer(readFileSync(join(CERTS_DIR, file), 'utf8'));
}

test('exports parseCert, InvalidAssetError, DecompressionError', () => {
  assert.equal(typeof parseCert, 'function');
  assert.equal(InvalidAssetError.prototype instanceof Error, true);
  assert.equal(DecompressionError.prototype instanceof Error, true);
});

test('expected-classification.json lists exactly the 11 golden certificates', () => {
  assert.equal(expected.certificates.length, 11);
  const onDisk = readdirSync(CERTS_DIR).filter((f) => f.endsWith('.crt')).sort();
  assert.deepEqual(onDisk, Object.keys(PER_FILE).sort());
  for (const entry of expected.certificates) {
    const file = entry.file.replace(/^certs\//, '');
    assert.ok(PER_FILE[file], `no PER_FILE row for golden cert ${file}`);
    const raw = readFileSync(join(CERTS_DIR, file));
    assert.equal(createHash('sha256').update(raw).digest('hex'), entry.sha256, `sha256 mismatch for ${file}`);
  }
});

for (const [file, per] of Object.entries(PER_FILE)) {
  test(`parseCert extracts ${file} (sig OID, SPKI OID, key bytes, validity, DN)`, () => {
    const entry = expectedByFile.get(file);
    assert.ok(entry, `expected-classification.json has no row for ${file}`);

    const der = certBytes(file);
    const asset = parseCert(der);

    // Structure + identity
    assert.equal(asset.type, 'certificate');
    assert.equal(asset.version, 3);
    assert.ok(Buffer.isBuffer(asset.serialNumber) && asset.serialNumber.length > 0);
    assert.ok(Buffer.isBuffer(asset.der));
    assert.deepEqual(asset.der, der);

    // Signature algorithm OID + cross-check against the OID registry/constants
    assert.equal(asset.signatureAlgorithm.oid, per.sigOid);
    assert.equal(asset.tbsSignatureAlgorithm.oid, per.sigOid, 'tbsCertificate.signature must equal top-level signatureAlgorithm');
    const sigRegistry = OID_TABLE[per.sigOid] || CLASSICAL_OIDS[per.sigOid];
    assert.ok(sigRegistry, `signature OID ${per.sigOid} not in constants registry`);
    if (OID_TABLE[per.sigOid]) {
      // PQ registry: parameterSetIdentifier carries the expected algorithm name
      assert.equal(sigRegistry.parameterSetIdentifier, entry.signatureAlgorithm);
      assert.equal(PARAMETER_SETS[sigRegistry.parameterSetIdentifier].family, entry.signature.family);
    } else {
      assert.equal(sigRegistry.name, entry.signatureAlgorithm);
    }

    // SPKI: OID, key bytes, parameters
    assert.equal(asset.subjectPublicKeyInfo.oid, per.spkiOid);
    assert.equal(asset.subjectPublicKeyInfo.keyBytes.length, per.keyBytes);
    assert.deepEqual(asset.keyBytes, asset.subjectPublicKeyInfo.keyBytes);
    const spkiRegistry = OID_TABLE[per.spkiOid] || CLASSICAL_OIDS[per.spkiOid];
    assert.ok(spkiRegistry, `SPKI OID ${per.spkiOid} not in constants registry`);
    assert.ok(asset.subjectPublicKeyInfo.parameters !== undefined, 'SPKI parameters field must be present (buffer or null)');

    // Validity (UTCTIME, DER-parsed — never new Date(string))
    assert.equal(asset.notBefore.getTime(), parseOpenSslDate(entry.notBefore).getTime(), 'notBefore mismatch');
    assert.equal(asset.notAfter.getTime(), parseOpenSslDate(entry.notAfter).getTime(), 'notAfter mismatch');
    assert.ok(asset.notBefore.getTime() < asset.notAfter.getTime());

    // DN (RFC 2253 rendering; all golden certs are self-signed, verified via openssl 2026-11-13)
    assert.equal(asset.subjectDn, entry.subjectDn);
    assert.equal(asset.issuerDn, entry.subjectDn, 'golden certs are self-signed');
  });
}