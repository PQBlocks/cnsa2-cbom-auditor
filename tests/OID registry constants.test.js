// S-01 — OID registry constants.
// Acceptance (spec/spec.md S-01): `lib/constants.js` exports OID_TABLE,
// CLASSICAL_OIDS, PARAMETER_SETS as frozen objects built from
// brief/research-brief.md §3.1 (OID registry) and §2 (parameter sets).
// Byte-for-byte oracle: golden-vectors/oid-classification.json.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const GOLDEN_PATH = path.join(ROOT, 'golden-vectors', 'oid-classification.json');
const golden = JSON.parse(fs.readFileSync(GOLDEN_PATH, 'utf8'));
const goldenRows = golden.classifications;
const goldenPq = goldenRows.filter((r) =>
  ['kem', 'signature'].includes(r.primitive) && r.oid.startsWith('2.16.840.1.101.3.4.'));
const goldenClassical = goldenRows.filter((r) => !goldenPq.includes(r));

const constants = require(path.join(ROOT, 'lib', 'constants.js'));
const { OID_TABLE, CLASSICAL_OIDS, PARAMETER_SETS } = constants;

// --- Frozen, exported objects -------------------------------------------------

test('exports OID_TABLE, CLASSICAL_OIDS, PARAMETER_SETS', () => {
  assert.ok(OID_TABLE && typeof OID_TABLE === 'object');
  assert.ok(CLASSICAL_OIDS && typeof CLASSICAL_OIDS === 'object');
  assert.ok(PARAMETER_SETS && typeof PARAMETER_SETS === 'object');
});

test('all three exports are frozen (and their entries are frozen)', () => {
  assert.ok(Object.isFrozen(OID_TABLE));
  assert.ok(Object.isFrozen(CLASSICAL_OIDS));
  assert.ok(Object.isFrozen(PARAMETER_SETS));
  for (const [k, v] of Object.entries(OID_TABLE)) {
    assert.ok(Object.isFrozen(v), `OID_TABLE[${k}] not frozen`);
  }
  for (const [k, v] of Object.entries(CLASSICAL_OIDS)) {
    assert.ok(Object.isFrozen(v), `CLASSICAL_OIDS[${k}] not frozen`);
  }
  for (const [k, v] of Object.entries(PARAMETER_SETS)) {
    assert.ok(Object.isFrozen(v), `PARAMETER_SETS[${k}] not frozen`);
  }
});

// --- Byte-for-byte match to the golden vector ---------------------------------

test('OID_TABLE matches every PQ row of oid-classification.json byte-for-byte', () => {
  assert.equal(Object.keys(OID_TABLE).length, goldenPq.length);
  for (const row of goldenPq) {
    assert.ok(OID_TABLE[row.oid], `missing PQ OID ${row.oid}`);
    // Byte-for-byte: same key order, same values, same JSON serialization.
    assert.equal(JSON.stringify(OID_TABLE[row.oid]), JSON.stringify(row),
      `OID ${row.oid} does not match golden vector byte-for-byte`);
  }
});

test('CLASSICAL_OIDS matches every classical row of oid-classification.json byte-for-byte', () => {
  for (const row of goldenClassical) {
    assert.ok(CLASSICAL_OIDS[row.oid], `missing classical OID ${row.oid}`);
    assert.equal(JSON.stringify(CLASSICAL_OIDS[row.oid]), JSON.stringify(row),
      `OID ${row.oid} does not match golden vector byte-for-byte`);
  }
});

test('golden PQ coverage: exactly the 18 PQ OIDs from brief §3.1', () => {
  assert.deepEqual(Object.keys(OID_TABLE).sort(), goldenPq.map((r) => r.oid).sort());
});

// --- CLASSICAL_OIDS: the 12 from brief §3.1 ------------------------------------

test('CLASSICAL_OIDS contains exactly the 12 classical OIDs from brief §3.1', () => {
  assert.deepEqual(Object.keys(CLASSICAL_OIDS).sort(), [
    '1.2.840.10045.2.1',   // id-ecPublicKey
    '1.2.840.10045.3.1.7', // prime256v1
    '1.2.840.10045.4.3.2', // ecdsa-with-SHA256
    '1.2.840.10045.4.3.3', // ecdsa-with-SHA384
    '1.2.840.113549.1.1.1',  // rsaEncryption
    '1.2.840.113549.1.1.10', // RSASSA-PSS
    '1.2.840.113549.1.1.11', // sha256WithRSAEncryption
    '1.2.840.113549.1.1.12', // sha384WithRSAEncryption
    '1.2.840.113549.1.1.13', // sha512WithRSAEncryption
    '1.3.101.112',         // ED25519
    '1.3.101.113',         // ED448
    '1.3.132.0.34',        // secp384r1
  ].sort());
});

test('classical OIDs are all nistQuantumSecurityLevel 0 with the IR 8547 legacy status', () => {
  for (const [oid, entry] of Object.entries(CLASSICAL_OIDS)) {
    assert.equal(entry.oid, oid);
    assert.equal(entry.nistQuantumSecurityLevel, 0, `${oid} level`);
    assert.equal(entry.cnsa2_status, 'legacy-deprecated-after-2030-disallowed-after-2035',
      `${oid} cnsa2_status`);
    assert.equal(entry.parameterSetIdentifier, null, `${oid} parameterSetIdentifier`);
  }
});

// --- PARAMETER_SETS: exact values from brief §2 tables -------------------------

test('PARAMETER_SETS covers exactly the parameterSetIdentifier values in OID_TABLE', () => {
  const ids = Object.values(OID_TABLE)
    .map((e) => e.parameterSetIdentifier)
    .filter((v) => v !== null)
    .sort();
  assert.equal(ids.length, 18);
  assert.deepEqual(Object.keys(PARAMETER_SETS).sort(), ids);
});

test('ML-KEM parameter sets transcribe FIPS 203 Table 2/3 (brief §2.1)', () => {
  assert.deepEqual(PARAMETER_SETS['ML-KEM-512'], {
    family: 'ML-KEM', n: 256, q: 3329, k: 2, eta1: 3, eta2: 2, du: 10, dv: 4,
    ekBytes: 800, dkBytes: 1632, ctBytes: 768, ssBytes: 32,
    nistCategory: 1, cnsa2Compliant: false,
  });
  assert.deepEqual(PARAMETER_SETS['ML-KEM-768'], {
    family: 'ML-KEM', n: 256, q: 3329, k: 3, eta1: 2, eta2: 2, du: 10, dv: 4,
    ekBytes: 1184, dkBytes: 2400, ctBytes: 1088, ssBytes: 32,
    nistCategory: 3, cnsa2Compliant: false,
  });
  assert.deepEqual(PARAMETER_SETS['ML-KEM-1024'], {
    family: 'ML-KEM', n: 256, q: 3329, k: 4, eta1: 2, eta2: 2, du: 11, dv: 5,
    ekBytes: 1568, dkBytes: 3168, ctBytes: 1568, ssBytes: 32,
    nistCategory: 5, cnsa2Compliant: true,
  });
});

test('ML-DSA parameter sets transcribe FIPS 204 Table 2 (brief §2.2)', () => {
  assert.deepEqual(PARAMETER_SETS['ML-DSA-44'], {
    family: 'ML-DSA', privateKeyBytes: 2560, publicKeyBytes: 1312, signatureBytes: 2420,
    nistCategory: 2, cnsa2Compliant: false,
    note: 'category 2 (1 with a <192-bit RBG, IR 8547 Table 3 note 2)',
  });
  assert.deepEqual(PARAMETER_SETS['ML-DSA-65'], {
    family: 'ML-DSA', privateKeyBytes: 4032, publicKeyBytes: 1952, signatureBytes: 3309,
    nistCategory: 3, cnsa2Compliant: false,
  });
  assert.deepEqual(PARAMETER_SETS['ML-DSA-87'], {
    family: 'ML-DSA', privateKeyBytes: 4896, publicKeyBytes: 2592, signatureBytes: 4627,
    nistCategory: 5, cnsa2Compliant: true,
  });
});

test('SLH-DSA parameter sets transcribe FIPS 205 Table 2 (brief §2.3)', () => {
  const expected = {
    'SLH-DSA-SHA2-128s': { shape: '128s', n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, lgw: 4, m: 30, category: 1, pkBytes: 32, sigBytes: 7856 },
    'SLH-DSA-SHA2-128f': { shape: '128f', n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, lgw: 4, m: 34, category: 1, pkBytes: 32, sigBytes: 17088 },
    'SLH-DSA-SHA2-192s': { shape: '192s', n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17, lgw: 4, m: 39, category: 3, pkBytes: 48, sigBytes: 16224 },
    'SLH-DSA-SHA2-192f': { shape: '192f', n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33, lgw: 4, m: 42, category: 3, pkBytes: 48, sigBytes: 35664 },
    'SLH-DSA-SHA2-256s': { shape: '256s', n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, lgw: 4, m: 47, category: 5, pkBytes: 64, sigBytes: 29792 },
    'SLH-DSA-SHA2-256f': { shape: '256f', n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35, lgw: 4, m: 49, category: 5, pkBytes: 64, sigBytes: 49856 },
    'SLH-DSA-SHAKE-128s': { shape: '128s', n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, lgw: 4, m: 30, category: 1, pkBytes: 32, sigBytes: 7856 },
    'SLH-DSA-SHAKE-128f': { shape: '128f', n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, lgw: 4, m: 34, category: 1, pkBytes: 32, sigBytes: 17088 },
    'SLH-DSA-SHAKE-192s': { shape: '192s', n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17, lgw: 4, m: 39, category: 3, pkBytes: 48, sigBytes: 16224 },
    'SLH-DSA-SHAKE-192f': { shape: '192f', n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33, lgw: 4, m: 42, category: 3, pkBytes: 48, sigBytes: 35664 },
    'SLH-DSA-SHAKE-256s': { shape: '256s', n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, lgw: 4, m: 47, category: 5, pkBytes: 64, sigBytes: 29792 },
    'SLH-DSA-SHAKE-256f': { shape: '256f', n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35, lgw: 4, m: 49, category: 5, pkBytes: 64, sigBytes: 49856 },
  };
  for (const [id, shape] of Object.entries(expected)) {
    assert.deepEqual(PARAMETER_SETS[id], {
      family: 'SLH-DSA', hash: id.includes('SHA2') ? 'SHA2' : 'SHAKE',
      ...shape, cnsa2Compliant: false,
    }, id);
  }
});

test('only ML-KEM-1024 and ML-DSA-87 are cnsa2Compliant (brief §2.1/§2.2, CNSA 2.0 Level V)', () => {
  const compliant = Object.entries(PARAMETER_SETS)
    .filter(([, v]) => v.cnsa2Compliant)
    .map(([k]) => k)
    .sort();
  assert.deepEqual(compliant, ['ML-DSA-87', 'ML-KEM-1024']);
});

test('registry carries no unknown/junk OIDs; a random OID is absent', () => {
  assert.equal(OID_TABLE['1.2.3.4.5'], undefined);
  assert.equal(CLASSICAL_OIDS['1.2.3.4.5'], undefined);
  assert.equal(PARAMETER_SETS['ML-KEM-999'], undefined);
});
