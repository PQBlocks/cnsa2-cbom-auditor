'use strict';

// S-10 — Fallback parser (@peculiar/x509) for Node < 26.
// Contract: lib/fallback.js wraps @peculiar/x509 and produces the SAME Asset
// shape as lib/x509.js parseCert (the native/pure-JS parser). The 11 golden
// certificates must classify identically through both paths.
// Node 24 is not available on this machine (checked: `which node24` empty),
// so the Node<26 gate is exercised via explicit version strings (mocked), and
// the parser itself is exercised for real, on this Node, against the native
// parser as oracle.

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, readdirSync } = require('node:fs');
const { join, dirname } = require('node:path');

// The contract spells this file's path with a slash inside the name
// (tests/Fallback parser (@peculiar/x509).test.js), which is a nested path,
// not a flat filename. LANE is therefore two levels up from __dirname.
const LANE = dirname(__dirname);
const CERTS_DIR = join(LANE, 'golden-vectors', 'certs');

const { parseCert } = require('../lib/x509.js');
const { classifyAsset } = require('../lib/classify.js');
const { parseCertFallback, isFallbackRequired, InvalidAssetError } = require('../lib/fallback.js');

function pemToDer(pemText) {
  return Buffer.from(
    pemText.split(/\r?\n/).filter((l) => l && !l.startsWith('-----')).join(''),
    'base64',
  );
}

const CERT_FILES = readdirSync(CERTS_DIR).filter((f) => f.endsWith('.crt')).sort();

function comparable(asset) {
  return {
    type: asset.type,
    version: asset.version,
    serialNumber: asset.serialNumber.toString('hex'),
    der: asset.der.toString('hex'),
    signatureAlgorithm: {
      oid: asset.signatureAlgorithm.oid,
      parameters: asset.signatureAlgorithm.parameters === null ? null : asset.signatureAlgorithm.parameters.toString('hex'),
    },
    tbsSignatureAlgorithm: {
      oid: asset.tbsSignatureAlgorithm.oid,
      parameters: asset.tbsSignatureAlgorithm.parameters === null ? null : asset.tbsSignatureAlgorithm.parameters.toString('hex'),
    },
    subjectPublicKeyInfo: {
      oid: asset.subjectPublicKeyInfo.oid,
      keyBytes: asset.subjectPublicKeyInfo.keyBytes.toString('hex'),
      parameters: asset.subjectPublicKeyInfo.parameters === null ? null : asset.subjectPublicKeyInfo.parameters.toString('hex'),
    },
    keyBytes: asset.keyBytes.toString('hex'),
    notBefore: asset.notBefore.getTime(),
    notAfter: asset.notAfter.getTime(),
    subjectDn: asset.subjectDn,
    issuerDn: asset.issuerDn,
  };
}

test('exports parseCertFallback, isFallbackRequired, InvalidAssetError', () => {
  assert.equal(typeof parseCertFallback, 'function');
  assert.equal(typeof isFallbackRequired, 'function');
  assert.equal(InvalidAssetError.prototype instanceof Error, true);
});

test('isFallbackRequired: Node < 26 requires the fallback, >= 26 does not', () => {
  assert.equal(isFallbackRequired('24.0.0'), true);
  assert.equal(isFallbackRequired('24.11.1'), true);
  assert.equal(isFallbackRequired('25.9.0'), true);
  assert.equal(isFallbackRequired('v25.9.0'), true);
  assert.equal(isFallbackRequired('26.0.0'), false);
  assert.equal(isFallbackRequired('26.13.0'), false);
  assert.equal(isFallbackRequired('27.0.0'), false);
});

test('isFallbackRequired: garbage version strings raise TypeError', () => {
  assert.throws(() => isFallbackRequired('banana'), TypeError);
  assert.throws(() => isFallbackRequired(''), TypeError);
  assert.throws(() => isFallbackRequired(26), TypeError);
  assert.throws(() => isFallbackRequired(null), TypeError);
});

test('this machine runs Node >= 26, so the real gate for process.versions.node is false', () => {
  const major = Number(process.versions.node.split('.')[0]);
  assert.ok(major >= 26, `expected Node >= 26, got ${process.versions.node}`);
  assert.equal(isFallbackRequired(process.versions.node), false);
});

test('golden directory holds exactly 11 certificates', () => {
  assert.equal(CERT_FILES.length, 11);
});

for (const file of CERT_FILES) {
  test(`fallback Asset is identical to native Asset for ${file} (mocked Node 24 path)`, () => {
    // Mocked Node<26 scenario: the version gate selects the fallback and the
    // fallback must produce the same Asset as the native parser.
    assert.equal(isFallbackRequired('24.11.1'), true);
    const der = pemToDer(readFileSync(join(CERTS_DIR, file), 'utf8'));

    const nativeAsset = parseCert(der);
    const fallbackAsset = parseCertFallback(der);

    assert.deepEqual(comparable(fallbackAsset), comparable(nativeAsset));

    // Buffer/Date/typed identity checks (shape, not just hex strings)
    assert.ok(Buffer.isBuffer(fallbackAsset.serialNumber));
    assert.ok(Buffer.isBuffer(fallbackAsset.der));
    assert.ok(Buffer.isBuffer(fallbackAsset.keyBytes));
    assert.ok(fallbackAsset.notBefore instanceof Date);
    assert.ok(fallbackAsset.notAfter instanceof Date);
    assert.equal(fallbackAsset.type, 'certificate');
  });

  test(`fallback parameters are Buffer-or-null for ${file}`, () => {
    const der = pemToDer(readFileSync(join(CERTS_DIR, file), 'utf8'));
    const asset = parseCertFallback(der);
    for (const params of [
      asset.signatureAlgorithm.parameters,
      asset.tbsSignatureAlgorithm.parameters,
      asset.subjectPublicKeyInfo.parameters,
    ]) {
      assert.ok(params === null || Buffer.isBuffer(params), `parameters not Buffer-or-null: ${typeof params}`);
    }
  });

  test(`fallback cert classifies identically to native for ${file}`, () => {
    const der = pemToDer(readFileSync(join(CERTS_DIR, file), 'utf8'));
    const nativeC = classifyAsset(parseCert(der));
    const fallbackC = classifyAsset(parseCertFallback(der));
    assert.equal(fallbackC.verdict, nativeC.verdict);
    assert.equal(fallbackC.pqSecure, nativeC.pqSecure);
    assert.equal(fallbackC.cnsa20Compliant, nativeC.cnsa20Compliant);
    assert.equal(fallbackC.nistDisposition, nativeC.nistDisposition);
  });
}

test('garbage DER throws InvalidAssetError (not a @peculiar internal error)', () => {
  assert.throws(() => parseCertFallback(Buffer.from([0xde, 0xad, 0xbe, 0xef])), InvalidAssetError);
});

test('empty buffer throws InvalidAssetError', () => {
  assert.throws(() => parseCertFallback(Buffer.alloc(0)), InvalidAssetError);
});

test('PEM text fed as DER throws InvalidAssetError', () => {
  const pem = readFileSync(join(CERTS_DIR, 'ec-p256-sha256.crt'), 'utf8');
  assert.throws(() => parseCertFallback(Buffer.from(pem, 'utf8')), InvalidAssetError);
});

test('truncated certificate throws InvalidAssetError', () => {
  const der = pemToDer(readFileSync(join(CERTS_DIR, 'mldsa65.crt'), 'utf8'));
  assert.throws(() => parseCertFallback(der.subarray(0, 40)), InvalidAssetError);
});

test('non-buffer, non-string input throws InvalidAssetError', () => {
  assert.throws(() => parseCertFallback(42), InvalidAssetError);
  assert.throws(() => parseCertFallback(null), InvalidAssetError);
});

test('fallback Asset carries the exact native key set (no extra top-level keys)', () => {
  const der = pemToDer(readFileSync(join(CERTS_DIR, 'rsa2048-sha256.crt'), 'utf8'));
  const nativeKeys = Object.keys(parseCert(der)).sort();
  const fallbackKeys = Object.keys(parseCertFallback(der)).sort();
  assert.deepEqual(fallbackKeys, nativeKeys);
});

// --- Defensive-branch coverage for the internal normalisers (hostile inputs) ---
const { _internals } = require('../lib/fallback.js');
const { normalizeParameters, decodeTime, asBuffer, algorithmIdentifier } = _internals;

test('normalizeParameters: undefined -> null, explicit NULL -> empty Buffer', () => {
  assert.equal(normalizeParameters(undefined), null);
  assert.deepEqual(normalizeParameters(null), Buffer.alloc(0));
});

test('normalizeParameters: Buffer and typed-array inputs strip one TLV layer', () => {
  const tlv = Buffer.from('06082a8648ce3d030107', 'hex'); // OID TLV (P-256 namedCurve)
  assert.equal(normalizeParameters(tlv).toString('hex'), '2a8648ce3d030107');
  const view = new Uint8Array(tlv);
  assert.equal(normalizeParameters(view).toString('hex'), '2a8648ce3d030107');
  const ab = tlv.buffer.slice(tlv.byteOffset, tlv.byteOffset + tlv.byteLength);
  assert.equal(normalizeParameters(ab).toString('hex'), '2a8648ce3d030107');
});

test('normalizeParameters: long-form length TLV is stripped correctly', () => {
  const content = Buffer.alloc(200, 0xab); // 200 bytes, needs long-form length
  const tlv = Buffer.concat([Buffer.from([0x04, 0x81, 0xc8]), content]); // OCTET STRING, len 200
  assert.equal(normalizeParameters(tlv).length, 200);
  assert.equal(normalizeParameters(tlv)[0], 0xab);
});

test('normalizeParameters: malformed long-form length throws InvalidAssetError', () => {
  assert.throws(() => normalizeParameters(Buffer.from([0x30, 0x80])), InvalidAssetError); // 0x80 = indefinite
  assert.throws(() => normalizeParameters(Buffer.from([0x30, 0x82, 0x01])), InvalidAssetError); // truncated length bytes
});

test('normalizeParameters: declared content exceeding the buffer throws InvalidAssetError', () => {
  assert.throws(() => normalizeParameters(Buffer.from([0x06, 0x7f, 0x2a])), InvalidAssetError);
});

test('normalizeParameters: unsupported encoding throws InvalidAssetError', () => {
  assert.throws(() => normalizeParameters(42), InvalidAssetError);
  assert.throws(() => normalizeParameters('oid'), InvalidAssetError);
});

test('normalizeParameters: tiny buffers yield an empty Buffer', () => {
  assert.deepEqual(normalizeParameters(Buffer.from([0x00])), Buffer.alloc(0));
});

test('decodeTime: missing or invalid time values throw InvalidAssetError', () => {
  assert.throws(() => decodeTime(undefined, 'notBefore'), InvalidAssetError);
  assert.throws(() => decodeTime(null, 'notBefore'), InvalidAssetError);
  assert.throws(() => decodeTime({}, 'notBefore'), InvalidAssetError);
  assert.throws(() => decodeTime({ utcTime: new Date('not-a-date') }, 'notBefore'), InvalidAssetError);
});

test('decodeTime: generalTime Date instances are accepted', () => {
  const d = new Date(Date.UTC(2040, 0, 1));
  assert.equal(decodeTime({ generalTime: d }, 'notAfter').getTime(), d.getTime());
});

test('asBuffer: missing input and unsupported encodings throw InvalidAssetError', () => {
  assert.throws(() => asBuffer(undefined, 'serialNumber'), InvalidAssetError);
  assert.throws(() => asBuffer(null, 'serialNumber'), InvalidAssetError);
  assert.throws(() => asBuffer(42, 'serialNumber'), InvalidAssetError);
});

test('asBuffer: ArrayBuffer and views round-trip to Buffers', () => {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  assert.deepEqual(asBuffer(ab, 'x'), Buffer.from([1, 2, 3, 4]));
  assert.deepEqual(asBuffer(bytes, 'x'), Buffer.from([1, 2, 3, 4]));
});

test('algorithmIdentifier: missing/empty OID throws InvalidAssetError', () => {
  assert.throws(() => algorithmIdentifier(null, 'signatureAlgorithm'), InvalidAssetError);
  assert.throws(() => algorithmIdentifier({}, 'signatureAlgorithm'), InvalidAssetError);
  assert.throws(() => algorithmIdentifier({ algorithm: '' }, 'signatureAlgorithm'), InvalidAssetError);
});

test('algorithmIdentifier: absent parameters yield null', () => {
  assert.deepEqual(algorithmIdentifier({ algorithm: '1.2.3.4' }, 'x'), { oid: '1.2.3.4', parameters: null });
});

test('parseCertFallback: DER-valid but not a certificate is wrapped in InvalidAssetError', () => {
  // SEQUENCE { INTEGER 5 } — parseDer accepts any TLV; @peculiar must reject it.
  const notACert = Buffer.from('3003020105', 'hex');
  assert.throws(() => parseCertFallback(notACert), InvalidAssetError);
});

test('parseCertFallback: accepts ArrayBuffer and Uint8Array DER input', () => {
  const pem = readFileSync(join(CERTS_DIR, 'ed25519.crt'), 'utf8');
  const der = pemToDer(pem);
  const ab = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength);
  assert.equal(parseCertFallback(ab).type, 'certificate');
  assert.equal(parseCertFallback(new Uint8Array(der)).type, 'certificate');
});

test('isFallbackRequired: trims surrounding whitespace', () => {
  assert.equal(isFallbackRequired('  24.11.1  '), true);
  assert.equal(isFallbackRequired(' 26.13.0'), false);
});
