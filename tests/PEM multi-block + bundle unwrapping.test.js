'use strict';

// S-11 — PEM multi-block + bundle unwrapping.
// Contract (spec/spec.md S-11): lib/pem.js exports splitPemBlocks(text) ->
// string[]; PKCS#7/PKCS#12 detection via OID; unwrap to certs.
// Fixtures in tests/fixtures are real OpenSSL 3.6.5 output (see
// golden-vectors/README.md): a PKCS#7 bundle of three golden certificates,
// an encrypted PKCS#12 exported from a throwaway RSA key, and a plain
// multi-asset PEM file.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const LANE = path.join(__dirname, '..');
const LIB = path.join(LANE, 'lib');
const FIXTURES = path.join(__dirname, 'fixtures');

const {
  splitPemBlocks,
  detectPemType,
  detectBundleOid,
  extractCertsFromPkcs7,
  analyzePemBlocks,
} = require(path.join(LIB, 'pem'));
const { InvalidAssetError } = require(path.join(LIB, 'der'));
const { parseCert } = require(path.join(LIB, 'x509'));

const fixture = (name) => fs.readFileSync(path.join(FIXTURES, name), 'utf8');
const derOf = (pem) => Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
const subjectsOf = (certs) => certs.map((pem) => parseCert(derOf(pem)).subjectDn).sort();

const MULTI_PEM = fixture('multi.pem');
const P7B_PEM = fixture('bundle.p7b.pem');
const P12_PEM = fixture('encrypted-pkcs12.pem');
const P12_DER = fs.readFileSync(path.join(FIXTURES, 'encrypted.pfx'));
const ED25519_PEM = fs.readFileSync(path.join(LANE, 'golden-vectors/certs/ed25519.crt'), 'utf8');

const BUNDLE_SUBJECTS = [
  'CN=pqblocks-gv-ec-p256-sha256',
  'CN=pqblocks-gv-ed25519',
  'CN=pqblocks-gv-rsa2048-sha256',
];

// --- splitPemBlocks --------------------------------------------------------

test('splitPemBlocks returns every PEM block in a multi-asset file', () => {
  const blocks = splitPemBlocks(MULTI_PEM);
  assert.equal(blocks.length, 4);
  assert.ok(blocks[0].startsWith('-----BEGIN CERTIFICATE-----'));
  assert.ok(blocks[0].endsWith('-----END CERTIFICATE-----'));
  assert.ok(blocks[3].startsWith('-----BEGIN PUBLIC KEY-----'));
});

test('splitPemBlocks preserves the exact blocked body of a single-block file', () => {
  const blocks = splitPemBlocks(ED25519_PEM);
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0], ED25519_PEM.trim());
});

test('splitPemBlocks ignores text before, between and after blocks', () => {
  const text = `leading junk\n${MULTI_PEM}\ntrailing junk\n`;
  const blocks = splitPemBlocks(text);
  assert.equal(blocks.length, 4);
  assert.equal(blocks[0], splitPemBlocks(MULTI_PEM)[0]);
  assert.equal(blocks[2], splitPemBlocks(MULTI_PEM)[2]);
});

test('splitPemBlocks normalizes CRLF line endings to LF', () => {
  const lf = splitPemBlocks(ED25519_PEM);
  const crlf = splitPemBlocks(ED25519_PEM.replace(/\n/g, '\r\n'));
  assert.equal(crlf.length, 1);
  assert.equal(crlf[0], lf[0]);
  assert.ok(!crlf[0].includes('\r'));
});

test('splitPemBlocks returns an empty array when no PEM block is present', () => {
  assert.deepEqual(splitPemBlocks('hello world, no armor here'), []);
});

test('splitPemBlocks does not emit a block for an unterminated BEGIN marker', () => {
  assert.deepEqual(splitPemBlocks('-----BEGIN CERTIFICATE-----\nMIIB'), []);
});

test('splitPemBlocks rejects non-string input', () => {
  assert.throws(() => splitPemBlocks(null), TypeError);
  assert.throws(() => splitPemBlocks(Buffer.from(MULTI_PEM)), TypeError);
});

// --- detectPemType ---------------------------------------------------------

test('detectPemType maps every supported PEM label', () => {
  const cases = [
    ['CERTIFICATE', 'certificate'],
    ['X509 CERTIFICATE', 'certificate'],
    ['TRUSTED CERTIFICATE', 'certificate'],
    ['PUBLIC KEY', 'publicKey'],
    ['PRIVATE KEY', 'privateKey'],
    ['RSA PRIVATE KEY', 'privateKey'],
    ['EC PRIVATE KEY', 'privateKey'],
    ['ENCRYPTED PRIVATE KEY', 'privateKey'],
    ['PKCS7', 'pkcs7'],
    ['PKCS#7', 'pkcs7'],
    ['PKCS12', 'pkcs12'],
    ['PKCS#12', 'pkcs12'],
    ['CERTIFICATE REQUEST', 'csr'],
    ['SOMETHING ELSE', 'unknown'],
    ['certificate', 'certificate'],
  ];
  for (const [label, expected] of cases) {
    assert.equal(detectPemType(label), expected, `label ${label}`);
  }
});

test('detectPemType rejects non-string input', () => {
  assert.throws(() => detectPemType(null), TypeError);
});

// --- detectBundleOid -------------------------------------------------------

test('detectBundleOid identifies a PKCS#7 SignedData by its ContentInfo OID', () => {
  assert.equal(detectBundleOid(derOf(P7B_PEM)), 'pkcs7');
});

test('detectBundleOid identifies a PKCS#12 PFX by its ContentInfo OID', () => {
  assert.equal(detectBundleOid(P12_DER), 'pkcs12');
});

test('detectBundleOid returns null for a plain certificate', () => {
  assert.equal(detectBundleOid(derOf(ED25519_PEM)), null);
});

test('detectBundleOid rejects bytes that are not DER', () => {
  assert.throws(() => detectBundleOid(Buffer.from('not der at all')), InvalidAssetError);
  assert.throws(() => detectBundleOid(Buffer.alloc(0)), InvalidAssetError);
});

// --- extractCertsFromPkcs7 -------------------------------------------------

test('extractCertsFromPkcs7 unwraps all certificates from a real PKCS#7 bundle', () => {
  const certs = extractCertsFromPkcs7(P7B_PEM);
  assert.equal(certs.length, 3);
  assert.deepEqual(subjectsOf(certs), BUNDLE_SUBJECTS);
});

test('extractCertsFromPkcs7 returns DER identical to the source certificates', () => {
  const certs = extractCertsFromPkcs7(P7B_PEM);
  assert.deepEqual(
    certs.map((pem) => derOf(pem).toString('hex')).sort(),
    [
      fs.readFileSync(path.join(LANE, 'golden-vectors/certs/rsa2048-sha256.crt'), 'utf8'),
      fs.readFileSync(path.join(LANE, 'golden-vectors/certs/ec-p256-sha256.crt'), 'utf8'),
      fs.readFileSync(path.join(LANE, 'golden-vectors/certs/ed25519.crt'), 'utf8'),
    ].map((pem) => derOf(pem).toString('hex')).sort(),
  );
});

test('extractCertsFromPkcs7 accepts raw DER bytes', () => {
  const certs = extractCertsFromPkcs7(derOf(P7B_PEM));
  assert.equal(certs.length, 3);
});

test('extractCertsFromPkcs7 rejects a PEM block that is not PKCS#7', () => {
  assert.throws(() => extractCertsFromPkcs7(ED25519_PEM), InvalidAssetError);
});

test('extractCertsFromPkcs7 rejects a body that is not valid base64', () => {
  const broken = '-----BEGIN PKCS7-----\n!!!! not base64 !!!!\n-----END PKCS7-----';
  assert.throws(() => extractCertsFromPkcs7(broken), InvalidAssetError);
});

// --- analyzePemBlocks ------------------------------------------------------

test('analyzePemBlocks classifies each block of a multi-asset file', () => {
  const { blocks, results } = analyzePemBlocks(MULTI_PEM);
  assert.equal(blocks.length, 4);
  assert.deepEqual(results.map((r) => r.type), ['certificate', 'certificate', 'certificate', 'publicKey']);
  for (const r of results.slice(0, 3)) {
    assert.equal(r.certs.length, 1);
    assert.equal(r.error, undefined);
  }
});

test('analyzePemBlocks unwraps a real PKCS#7 bundle into three certificate PEM blocks', () => {
  const { results } = analyzePemBlocks(P7B_PEM);
  assert.equal(results.length, 1);
  assert.equal(results[0].type, 'pkcs7');
  assert.equal(results[0].certs.length, 3);
  assert.equal(results[0].error, undefined);
  assert.deepEqual(subjectsOf(results[0].certs), BUNDLE_SUBJECTS);
});

test('analyzePemBlocks reports an encrypted PKCS#12 bundle as pkcs12 with no extractable certificates', () => {
  const { results } = analyzePemBlocks(P12_PEM);
  assert.equal(results.length, 1);
  assert.equal(results[0].type, 'pkcs12');
  assert.deepEqual(results[0].certs, []);
  assert.match(results[0].reason, /encrypt|password|passphrase/i);
  assert.equal(results[0].error, undefined);
});

test('analyzePemBlocks detects PKCS#7 from the DER OID even when the PEM label is wrong', () => {
  // Mislabel a genuine SignedData bundle as CERTIFICATE: the OID must win.
  const mislabelled = P7B_PEM.replace(/PKCS7/g, 'CERTIFICATE');
  const { results } = analyzePemBlocks(mislabelled);
  assert.equal(results.length, 1);
  assert.equal(results[0].type, 'pkcs7');
  assert.equal(results[0].certs.length, 3);
});

test('analyzePemBlocks keeps scanning after a corrupted block', () => {
  const corrupted = '-----BEGIN PKCS7-----\nAAAA\n-----END PKCS7-----';
  const text = `${ED25519_PEM}${corrupted}${ED25519_PEM}`;
  const { results } = analyzePemBlocks(text);
  assert.equal(results.length, 3);
  assert.equal(results[0].type, 'certificate');
  assert.ok(results[1].error, 'corrupted block records an error');
  assert.deepEqual(results[1].certs, []);
  assert.equal(results[2].type, 'certificate');
});

test('analyzePemBlocks returns empty arrays for text without PEM blocks', () => {
  assert.deepEqual(analyzePemBlocks('no armor here'), { blocks: [], results: [] });
});

test('analyzePemBlocks rejects non-string input', () => {
  assert.throws(() => analyzePemBlocks(null), TypeError);
});
