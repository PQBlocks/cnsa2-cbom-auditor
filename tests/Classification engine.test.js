'use strict';
// S-06 — Classification engine
// Acceptance (spec/spec.md S-06): `lib/classify.js` exports `classifyAsset(asset) -> Classification`
// implementing the decision DAG from brief §2.5. Test: all 11 certs + 12 SPKIs produce exact expected verdicts.
//
// Oracle discipline (R15/R22): for the 11 certificates every classification field is
// asserted against golden-vectors/expected/expected-classification.json — an independent
// OpenSSL-derived oracle (derive-expected.mjs) — never against the product's own output.
// The SPKI oracle (keys[]) carries oid + keyOctets. Verdicts for all 23 assets are
// hand-written below from brief §2.5 + §2.4 (IR 8547 Tables 2/4) and are never computed
// by calling classifyAsset. (An earlier draft derived the expectation from
// classifyAsset's own return value, so it could not fail; that test was removed.)

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { readFileSync } = require('node:fs');
const { parseCert } = require('../lib/x509.js');
const { parseSpki } = require('../lib/spki.js');
const { OID_TABLE, CLASSICAL_OIDS } = require('../lib/constants.js');
const { InvalidAssetError } = require('../lib/der.js');
const { classifyAsset } = require('../src/classify.js');

const LANE = path.dirname(__dirname);
const oracle = JSON.parse(
  readFileSync(path.join(LANE, 'golden-vectors', 'expected', 'expected-classification.json'), 'utf8')
);

function pemToDer(pemText) {
  const lines = pemText.split(/\r?\n/);
  const body = lines.filter((l) => l && !l.startsWith('-----')).join('');
  return Buffer.from(body, 'base64');
}

function readPem(relPath) {
  return readFileSync(path.join(LANE, 'golden-vectors', relPath), 'utf8');
}

// ---------------------------------------------------------------------------
// Hand-written expected verdicts, derived from brief §2.5 (decision DAG) and
// §2.4 (IR 8547 Tables 2/4). One entry per golden asset, 23 total. Recorded
// verdict rule (only mapping that makes no false statement for a CNSA 2.0
// auditor): required-level-v -> compliant; legacy classical -> deprecated
// (IR 8547 deprecated-2030 / disallowed-2035); other known PQ statuses (PQ
// below Level V, SLH-DSA absent from CNSA 2.0 Table IV) -> disallowed;
// unregistered OID -> unknown (§2.5 non-negotiable rule).
// ---------------------------------------------------------------------------
const EXPECTED_VERDICTS = {
  // certificates (11)
  'certs/ec-p256-sha256.crt': 'deprecated',   // ECDSA classical; IR 8547 deprecated-2030
  'certs/ec-p384-sha384.crt': 'deprecated',   // ECDSA classical; IR 8547 deprecated-2030
  'certs/ed25519.crt': 'deprecated',          // EdDSA classical; IR 8547 deprecated-2030
  'certs/mldsa44.crt': 'disallowed',          // FIPS 204 approved, category 2 < CNSA 2.0 Level V
  'certs/mldsa65.crt': 'disallowed',          // FIPS 204 approved, category 3 < CNSA 2.0 Level V
  'certs/mldsa87.crt': 'compliant',           // ML-DSA-87 = category 5 = CNSA 2.0 Level V
  'certs/rsa2048-sha256.crt': 'deprecated',   // RSA classical; IR 8547 deprecated-2030
  'certs/rsa3072-sha384.crt': 'deprecated',
  'certs/rsa4096-sha512.crt': 'deprecated',
  'certs/slhdsa-sha2-128s.crt': 'disallowed', // FIPS 205 approved; NOT in CNSA 2.0 Table IV
  'certs/slhdsa-shake-256f.crt': 'disallowed',// category 5 but still NOT CNSA 2.0 (P4 trap)
  // keys (12)
  'spki/ec-p256-sha256.spki.pem': 'deprecated',
  'spki/ec-p384-sha384.spki.pem': 'deprecated',
  'spki/ed25519.spki.pem': 'deprecated',
  'spki/mldsa44.spki.pem': 'disallowed',
  'spki/mldsa65.spki.pem': 'disallowed',
  'spki/mldsa87.spki.pem': 'compliant',
  'spki/mlkem1024.spki.pem': 'compliant',     // ML-KEM-1024 = category 5 = CNSA 2.0 Level V
  'spki/rsa2048-sha256.spki.pem': 'deprecated',
  'spki/rsa3072-sha384.spki.pem': 'deprecated',
  'spki/rsa4096-sha512.spki.pem': 'deprecated',
  'spki/slhdsa-sha2-128s.spki.pem': 'disallowed',
  'spki/slhdsa-shake-256f.spki.pem': 'disallowed',
};

const MLDSA87_OID = '2.16.840.1.101.3.4.3.19';
const MLDSA65_OID = '2.16.840.1.101.3.4.3.18';

test('exports classifyAsset', () => {
  assert.equal(typeof classifyAsset, 'function');
});

// --- All 11 certificates: parse the real files, classify, compare to the oracle ---
test('all 11 certificates produce exact expected verdicts', () => {
  assert.equal(oracle.certificates.length, 11);
  for (const entry of oracle.certificates) {
    const asset = parseCert(pemToDer(readPem(entry.file)));
    const c = classifyAsset(asset);

    assert.equal(c.verdict, EXPECTED_VERDICTS[entry.file], `${entry.file} verdict`);

    // The cert classification describes the SIGNATURE algorithm (EC-01: the key
    // verdict is emitted separately by the CBOM layer). Compare every oracle field.
    assert.equal(c.pqSecure, entry.signature.pqSecure, `${entry.file} pqSecure vs oracle`);
    assert.equal(c.cnsa20Compliant, entry.signature.cnsa20Compliant, `${entry.file} cnsa20Compliant vs oracle`);
    assert.equal(c.nistDisposition, entry.signature.nistDisposition, `${entry.file} nistDisposition vs oracle`);
    assert.equal(c.nistQuantumSecurityLevel, entry.signature.nistQuantumSecurityLevel,
      `${entry.file} nistQuantumSecurityLevel vs oracle`);
    assert.equal(c.family, entry.signature.family, `${entry.file} family vs oracle`);
    assert.equal(c.parameterSetIdentifier, entry.signature.paramSet,
      `${entry.file} parameterSetIdentifier vs oracle`);
    assert.equal(c.oid, entry.signature.oid ?? asset.signatureAlgorithm.oid, `${entry.file} oid echoed`);

    // The subject key of every golden cert embeds an SPKI with the same
    // quantum-relevant classification (self-signed, same family); the oracle
    // records both and they must agree.
    assert.equal(c.pqSecure, entry.publicKey.pqSecure, `${entry.file} key pqSecure vs oracle`);
    assert.equal(c.cnsa20Compliant, entry.publicKey.cnsa20Compliant, `${entry.file} key cnsa20Compliant vs oracle`);
  }
});

// --- All 12 SPKIs: parse the real files, classify, compare to the oracle ---
test('all 12 SPKIs produce exact expected verdicts', () => {
  assert.equal(oracle.keys.length, 12);
  for (const entry of oracle.keys) {
    const parsed = parseSpki(pemToDer(readPem(entry.file)));
    // oid + key length against the OpenSSL oracle (P1: length is measured, never guessed)
    assert.equal(parsed.oid, entry.oid, `${entry.file} oid vs oracle`);
    assert.equal(parsed.keyBytes.length, entry.keyOctets, `${entry.file} key octets vs oracle`);

    const c = classifyAsset(parsed);
    assert.equal(c.verdict, EXPECTED_VERDICTS[entry.file], `${entry.file} verdict`);
    assert.equal(c.oid, entry.oid, `${entry.file} oid echoed`);
    // PQ classification fields come from the registry (byte-for-byte verified
    // against oid-classification.json by the S-01 test file); classical rows
    // carry nistDisposition deprecated-2030-disallowed-2035 per IR 8547.
    assert.equal(c.nistDisposition,
      EXPECTED_VERDICTS[entry.file] === 'compliant' || EXPECTED_VERDICTS[entry.file] === 'disallowed'
        ? 'quantum-resistant'
        : 'deprecated-2030-disallowed-2035',
      `${entry.file} nistDisposition`);
    assert.equal(c.pqSecure, EXPECTED_VERDICTS[entry.file] !== 'deprecated', `${entry.file} pqSecure`);
    assert.equal(c.cnsa20Compliant, EXPECTED_VERDICTS[entry.file] === 'compliant',
      `${entry.file} cnsa20Compliant`);
  }
});

// --- Required fields (Classification shape) ---
test('Classification object has all required fields', () => {
  const asset = parseCert(pemToDer(readPem('certs/mldsa87.crt')));
  const c = classifyAsset(asset);
  for (const key of ['verdict', 'pqSecure', 'cnsa20Compliant', 'nistDisposition', 'deadline', 'reason']) {
    assert.ok(key in c, `missing key ${key}`);
  }
});

test('verdict values are valid enum members', () => {
  const allowed = ['compliant', 'deprecated', 'disallowed', 'unknown'];
  for (const entry of oracle.certificates) {
    const c = classifyAsset(parseCert(pemToDer(readPem(entry.file))));
    assert.ok(allowed.includes(c.verdict), `invalid verdict ${c.verdict}`);
  }
});

// --- P4 trap: category 5 does NOT imply CNSA 2.0 compliant ---
test('SLH-DSA-SHAKE-256f is pq-secure but NOT CNSA 2.0 compliant (P4 trap)', () => {
  const asset = parseCert(pemToDer(readPem('certs/slhdsa-shake-256f.crt')));
  const c = classifyAsset(asset);
  assert.equal(c.pqSecure, true);
  assert.equal(c.cnsa20Compliant, false);
  assert.equal(c.verdict, 'disallowed');
  assert.equal(c.nistQuantumSecurityLevel, 5); // category 5, yet...
  assert.equal(c.cnsa20Compliant, false);      // ...not CNSA 2.0 (P4)
});

test('ML-DSA-87 is compliant; ML-DSA-65 is disallowed', () => {
  const asset87 = parseCert(pemToDer(readPem('certs/mldsa87.crt')));
  assert.equal(classifyAsset(asset87).verdict, 'compliant');
  assert.equal(classifyAsset(asset87).cnsa20Compliant, true);

  const asset65 = parseCert(pemToDer(readPem('certs/mldsa65.crt')));
  assert.equal(classifyAsset(asset65).verdict, 'disallowed');
  assert.equal(classifyAsset(asset65).cnsa20Compliant, false);
  assert.equal(classifyAsset(asset65).pqSecure, true); // NIST-approved, not CNSA 2.0
});

// --- §2.5 non-negotiable rule: unrecognized OID -> unknown, raw OID emitted ---
test('unrecognized OID classifies as unknown with the raw OID in the reason (EC-08)', () => {
  const c = classifyAsset({ oid: '1.2.3.4.5' });
  assert.equal(c.verdict, 'unknown');
  assert.equal(c.pqSecure, false);
  assert.equal(c.cnsa20Compliant, false);
  assert.equal(c.nistDisposition, 'unknown');
  assert.equal(c.deadline, 'N/A');
  assert.ok(c.reason.includes('1.2.3.4.5'), `reason must carry the raw OID, got: ${c.reason}`);
  assert.ok(!('nistQuantumSecurityLevel' in c),
    'unknown assets must omit nistQuantumSecurityLevel (P2/EC-08: 0 means "none met", not unreadable)');
});

test('unknown-OID certificate classifies unknown from the signature OID (EC-08)', () => {
  const c = classifyAsset({
    signatureAlgorithm: { oid: '1.2.3.4.5' },
    subjectPublicKeyInfo: { oid: MLDSA87_OID },
  });
  assert.equal(c.verdict, 'unknown');
  assert.ok(c.reason.includes('1.2.3.4.5'));
});

// --- negative tests: garbage in must throw a loud, catchable error ---
test('null/undefined/non-object asset throws InvalidAssetError', () => {
  assert.throws(() => classifyAsset(null), InvalidAssetError);
  assert.throws(() => classifyAsset(undefined), InvalidAssetError);
  assert.throws(() => classifyAsset('garbage'), InvalidAssetError);
  assert.throws(() => classifyAsset(42), InvalidAssetError);
});

test('asset object without any classifiable OID throws InvalidAssetError', () => {
  assert.throws(() => classifyAsset({}), InvalidAssetError);
  assert.throws(() => classifyAsset({ signatureAlgorithm: {} }), InvalidAssetError);
  assert.throws(() => classifyAsset({ oid: 42 }), InvalidAssetError);
});

// --- deadlines (brief §2.5: EARLIEST applicable; §2.4 IR 8547 + OMB M-26-15) ---
test('classical assets carry the 2030-12-31 IR 8547/OMB M-26-15 deadline', () => {
  const asset = parseCert(pemToDer(readPem('certs/rsa2048-sha256.crt')));
  assert.equal(classifyAsset(asset).deadline, '2030-12-31');
});

test('PQ assets carry no IR 8547 decay deadline (N/A; asset-class dates belong to findings)', () => {
  const asset = parseCert(pemToDer(readPem('certs/mldsa87.crt')));
  assert.equal(classifyAsset(asset).deadline, 'N/A');
});

// --- full registry sweep: every OID row maps to a verdict per its status ---
test('every PQ registry row: only required-level-v is compliant; other PQ statuses disallowed', () => {
  for (const [oid, row] of Object.entries(OID_TABLE)) {
    const c = classifyAsset({ oid });
    assert.equal(c.pqSecure, true, `pqSecure for ${oid}`);
    if (row.cnsa2_status === 'required-level-v') {
      assert.equal(c.verdict, 'compliant', `verdict for ${oid}`);
      assert.equal(c.cnsa20Compliant, true, `cnsa for ${oid}`);
    } else {
      assert.equal(c.verdict, 'disallowed', `verdict for ${oid}`);
      assert.equal(c.cnsa20Compliant, false, `cnsa for ${oid}`);
    }
    assert.equal(c.nistQuantumSecurityLevel, row.nistQuantumSecurityLevel, `level for ${oid}`);
    assert.equal(c.parameterSetIdentifier, row.parameterSetIdentifier, `paramSet for ${oid}`);
  }
});

test('every classical registry row: not pq-secure, not CNSA, deprecated, 2030 deadline', () => {
  for (const [oid] of Object.entries(CLASSICAL_OIDS)) {
    const c = classifyAsset({ oid });
    assert.equal(c.pqSecure, false, `pqSecure for ${oid}`);
    assert.equal(c.cnsa20Compliant, false, `cnsa for ${oid}`);
    assert.equal(c.verdict, 'deprecated', `verdict for ${oid}`);
    assert.equal(c.nistDisposition, 'deprecated-2030-disallowed-2035', `disposition for ${oid}`);
    assert.equal(c.deadline, '2030-12-31', `deadline for ${oid}`);
  }
});
