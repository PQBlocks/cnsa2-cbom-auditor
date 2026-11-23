'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parsePrivateKey, InvalidAssetError } = require('../lib/pkcs8.js');

// ---------------------------------------------------------------------------
// Minimal DER writer. The previous revision of this file hand-rolled short-form
// lengths only (`Buffer.from([tag, content.length])`), which silently corrupted
// every body longer than 127 bytes — the expanded/both cases. These helpers
// encode lengths correctly (short form, or long form with a length-of-length).
// ---------------------------------------------------------------------------
function derLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

// OID -> DER content bytes (X.690 §8.19: first subidentifier = arc0*40 + arc1,
// remaining arcs base-128 with continuation bits).
function encodeOid(dotted) {
  const arcs = dotted.split('.').map((s) => Number(s));
  assert.ok(arcs.length >= 2 && arcs.every((a) => Number.isInteger(a)), `bad OID ${dotted}`);
  const values = [arcs[0] * 40 + arcs[1], ...arcs.slice(2)];
  const bytes = [];
  for (const value of values) {
    if (value < 128) {
      bytes.push(value);
      continue;
    }
    const stack = [value & 0x7f];
    let v = value >>> 7;
    while (v > 0) {
      stack.unshift(v & 0x7f);
      v >>>= 7;
    }
    for (let i = 0; i < stack.length - 1; i++) stack[i] |= 0x80;
    bytes.push(...stack);
  }
  return Buffer.from(bytes);
}

function encodeInteger(value) {
  assert.ok(value === 0 || value === 1, 'this fixture builder only needs v0/v1');
  return Buffer.from([value]);
}

// Build PKCS#8 PrivateKeyInfo (RFC 5208) / OneAsymmetricKey (RFC 5958, v1).
function buildPkcs8PrivateKey(oid, privateKeyDer, { version = 0, publicKey = null } = {}) {
  const versionField = tlv(0x02, encodeInteger(version));
  const algId = tlv(0x30, tlv(0x06, encodeOid(oid)));
  const privateKeyOctet = tlv(0x04, privateKeyDer);

  let content = Buffer.concat([versionField, algId, privateKeyOctet]);
  if (publicKey) {
    // [1] publicKey BIT STRING — present in a v2 OneAsymmetricKey.
    content = Buffer.concat([content, tlv(0x81, publicKey)]);
  }
  return tlv(0x30, content);
}

// Build the ML-KEM private-key CHOICE element (RFC 9935 §6 / brief §3.3),
// which is the *content* of the PKCS#8 `privateKey` OCTET STRING.
//   seed       -> [0] IMPLICIT OCTET STRING (64 bytes)          tag 0x80
//   expanded   -> OCTET STRING (dkBytes)                         tag 0x04
//   both       -> SEQUENCE { seed, expanded }                    tag 0x30
function buildMlKemPrivateKey(format, paramSet) {
  const sizes = {
    'ML-KEM-512': { seed: 64, dkBytes: 1632 },
    'ML-KEM-768': { seed: 64, dkBytes: 2400 },
    'ML-KEM-1024': { seed: 64, dkBytes: 3168 },
  };
  const { seed, dkBytes } = sizes[paramSet];

  const seedBytes = Buffer.alloc(seed);
  seedBytes.fill(0xaa);
  const expandedBytes = Buffer.alloc(dkBytes);
  expandedBytes.fill(0xbb);

  if (format === 'seed') return tlv(0x80, seedBytes);
  if (format === 'expanded') return tlv(0x04, expandedBytes);
  if (format === 'both') {
    return tlv(0x30, Buffer.concat([tlv(0x80, seedBytes), tlv(0x04, expandedBytes)]));
  }
  throw new Error(`Unknown format: ${format}`);
}

// ML-KEM OIDs (RFC 9935 §3).
const ML_KEM_OIDS = {
  'ML-KEM-512': '2.16.840.1.101.3.4.4.1',
  'ML-KEM-768': '2.16.840.1.101.3.4.4.2',
  'ML-KEM-1024': '2.16.840.1.101.3.4.4.3',
};

test('exports parsePrivateKey', () => {
  assert.equal(typeof parsePrivateKey, 'function');
});

test('parsePrivateKey rejects non-Buffer/string input', () => {
  assert.throws(() => parsePrivateKey(null), { name: 'InvalidAssetError' });
  assert.throws(() => parsePrivateKey(123), { name: 'InvalidAssetError' });
  assert.throws(() => parsePrivateKey({}), { name: 'InvalidAssetError' });
});

test('parsePrivateKey rejects empty input', () => {
  assert.throws(() => parsePrivateKey(Buffer.alloc(0)), { name: 'InvalidAssetError' });
});

test('parsePrivateKey rejects non-SEQUENCE input', () => {
  // Just an INTEGER
  assert.throws(() => parsePrivateKey(Buffer.from([0x02, 0x01, 0x00])), { name: 'InvalidAssetError' });
});

for (const [paramSet, oid] of Object.entries(ML_KEM_OIDS)) {
  for (const format of ['seed', 'expanded', 'both']) {
    test(`parsePrivateKey extracts ${paramSet} ${format} format`, () => {
      const privateKeyDer = buildMlKemPrivateKey(format, paramSet);
      const pkcs8Der = buildPkcs8PrivateKey(oid, privateKeyDer);
      const result = parsePrivateKey(pkcs8Der);

      assert.ok(result, 'result must be truthy');
      assert.equal(result.oid, oid, 'OID must match');
      assert.equal(result.format, format, `format must be ${format}`);
      assert.equal(result.paramSet, paramSet, `paramSet must be ${paramSet}`);
      assert.ok(!result.keyMaterial, 'must not emit key material');
    });
  }
}

test('parsePrivateKey handles PEM input', () => {
  const paramSet = 'ML-KEM-1024';
  const oid = ML_KEM_OIDS[paramSet];
  const privateKeyDer = buildMlKemPrivateKey('seed', paramSet);
  const pkcs8Der = buildPkcs8PrivateKey(oid, privateKeyDer);

  // Wrap in PEM
  const b64 = pkcs8Der.toString('base64');
  const pemLines = [];
  for (let i = 0; i < b64.length; i += 64) {
    pemLines.push(b64.slice(i, i + 64));
  }
  const pem = `-----BEGIN PRIVATE KEY-----\n${pemLines.join('\n')}\n-----END PRIVATE KEY-----\n`;

  const result = parsePrivateKey(pem);
  assert.equal(result.oid, oid);
  assert.equal(result.format, 'seed');
  assert.equal(result.paramSet, paramSet);
});

test('parsePrivateKey rejects PKCS#8 with public key (v2) - not supported', () => {
  // v2 OneAsymmetricKey carries an optional [1] publicKey. The private-key
  // fields (version, algorithm, privateKey) are unchanged, so extraction must
  // still succeed; the public key is simply not part of the reported shape.
  const paramSet = 'ML-KEM-1024';
  const oid = ML_KEM_OIDS[paramSet];
  const privateKeyDer = buildMlKemPrivateKey('seed', paramSet);
  const pkcs8Der = buildPkcs8PrivateKey(oid, privateKeyDer, {
    version: 1,
    publicKey: Buffer.from([0x00]),
  });

  const result = parsePrivateKey(pkcs8Der);
  assert.equal(result.oid, oid);
  assert.equal(result.format, 'seed');
  assert.equal(result.paramSet, paramSet);
});

test('parsePrivateKey rejects unknown OID', () => {
  const unknownOid = '1.2.3.4.5.6.7.8.9';
  const privateKeyDer = buildMlKemPrivateKey('seed', 'ML-KEM-1024');
  const pkcs8Der = buildPkcs8PrivateKey(unknownOid, privateKeyDer);

  assert.throws(() => parsePrivateKey(pkcs8Der), { name: 'InvalidAssetError' });
});

test('parsePrivateKey handles invalid private key structure', () => {
  // Malformed private key (wrong tag)
  const paramSet = 'ML-KEM-1024';
  const oid = ML_KEM_OIDS[paramSet];
  const badPrivateKey = Buffer.from([0x02, 0x01, 0x00]); // just an integer
  const pkcs8Der = buildPkcs8PrivateKey(oid, badPrivateKey);

  assert.throws(() => parsePrivateKey(pkcs8Der), { name: 'InvalidAssetError' });
});

test('parsePrivateKey handles version != 0', () => {
  // Version 1 (v2 OneAsymmetricKey) without the optional publicKey.
  const paramSet = 'ML-KEM-1024';
  const oid = ML_KEM_OIDS[paramSet];
  const privateKeyDer = buildMlKemPrivateKey('seed', paramSet);
  const pkcs8Der = buildPkcs8PrivateKey(oid, privateKeyDer, { version: 1 });

  const result = parsePrivateKey(pkcs8Der);
  assert.equal(result.oid, oid);
  assert.equal(result.format, 'seed');
  assert.equal(result.paramSet, paramSet);
});

// ---------------------------------------------------------------------------
// Additional negative / boundary cases (garbage in => loud InvalidAssetError).
// ---------------------------------------------------------------------------

test('parsePrivateKey rejects a PEM string with no PRIVATE KEY block', () => {
  assert.throws(
    () => parsePrivateKey('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'),
    { name: 'InvalidAssetError' },
  );
});

test('parsePrivateKey rejects truncated DER (declared length exceeds buffer)', () => {
  // SEQUENCE claiming 5 content bytes but cut off mid-OID.
  assert.throws(
    () => parsePrivateKey(Buffer.from([0x30, 0x05, 0x30, 0x03, 0x06, 0x01])),
    { name: 'InvalidAssetError' },
  );
});

test('parsePrivateKey rejects trailing bytes after the PrivateKeyInfo SEQUENCE', () => {
  const oid = ML_KEM_OIDS['ML-KEM-512'];
  const pkcs8Der = buildPkcs8PrivateKey(oid, buildMlKemPrivateKey('seed', 'ML-KEM-512'));
  const padded = Buffer.concat([pkcs8Der, Buffer.from([0xde, 0xad])]);
  assert.throws(() => parsePrivateKey(padded), { name: 'InvalidAssetError' });
});

test('parsePrivateKey rejects an unrecognized private-key format tag', () => {
  const oid = ML_KEM_OIDS['ML-KEM-512'];
  // privateKey OCTET STRING whose content starts with 0x0c (a UTF8String tag) —
  // neither the [0] seed, nor an OCTET STRING expandedKey, nor a both SEQUENCE.
  const pkcs8Der = buildPkcs8PrivateKey(oid, Buffer.from([0x0c, 0x02, 0xde, 0xad]));
  assert.throws(() => parsePrivateKey(pkcs8Der), { name: 'InvalidAssetError' });
});

test('parsePrivateKey rejects a privateKey field that is not an OCTET STRING', () => {
  const oid = ML_KEM_OIDS['ML-KEM-512'];
  const versionField = tlv(0x02, Buffer.from([0x00]));
  const algId = tlv(0x30, tlv(0x06, encodeOid(oid)));
  const notAnOctetString = tlv(0x02, Buffer.from([0x00])); // INTEGER where OCTET STRING belongs
  const pkcs8Der = tlv(0x30, Buffer.concat([versionField, algId, notAnOctetString]));
  assert.throws(() => parsePrivateKey(pkcs8Der), { name: 'InvalidAssetError' });
});

test('parsePrivateKey result exposes exactly { oid, format, paramSet } (no key material)', () => {
  const oid = ML_KEM_OIDS['ML-KEM-1024'];
  const pkcs8Der = buildPkcs8PrivateKey(oid, buildMlKemPrivateKey('both', 'ML-KEM-1024'));
  const result = parsePrivateKey(pkcs8Der);
  assert.deepEqual(Object.keys(result).sort(), ['format', 'oid', 'paramSet']);
});
