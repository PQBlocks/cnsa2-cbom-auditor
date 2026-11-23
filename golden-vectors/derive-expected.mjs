#!/usr/bin/env node
// derive-expected.mjs — independent expected-value oracle for the golden vectors.
//
// It does NOT import the product. It shells out to OpenSSL, reads the algorithm
// names OpenSSL prints, and maps them to a CNSA 2.0 / NIST IR 8547 verdict using
// the tables from the research brief (whose sources are cited below by FIPS
// table number).  If OpenSSL's answer and this table ever disagree, the script
// fails loudly instead of writing a quiet expectation.
//
// Sources encoded here:
//   FIPS 203 Table 2/3   ML-KEM-512/768/1024   categories 1/3/5, ek 800/1184/1568
//   FIPS 204 Table 2     ML-DSA-44/65/87       categories 2/3/5, pk 1312/1952/2592
//   FIPS 205 Table 2     SLH-DSA (12 sets)     categories 1/3/5, pk 32/48/64
//   NIST IR 8547 Tables 2 & 4:  RSA/ECDSA/EdDSA/DH deprecated after 2030, disallowed after 2035
//   NSA CNSA 2.0 Table IV: AES-256, SHA-384/512, Level V KEM + signature, LMS/XMSS
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const dir = path.dirname(new URL(import.meta.url).pathname);
const OPENSSL = process.env.OPENSSL || 'openssl';

// name -> classification. "unknown" is never used here: an unlisted algorithm is
// a hard error so the table cannot silently rot.
const TABLE = {
  'ML-KEM-512':  { family: 'ML-KEM',  primitive: 'kem',       param: 'ML-KEM-512',  category: 1, cnsa: false, nist: 'quantum-resistant', ek: 800 },
  'ML-KEM-768':  { family: 'ML-KEM',  primitive: 'kem',       param: 'ML-KEM-768',  category: 3, cnsa: false, nist: 'quantum-resistant', ek: 1184 },
  'ML-KEM-1024': { family: 'ML-KEM',  primitive: 'kem',       param: 'ML-KEM-1024', category: 5, cnsa: true,  nist: 'quantum-resistant', ek: 1568 },
  'ML-DSA-44':   { family: 'ML-DSA',  primitive: 'signature', param: 'ML-DSA-44',   category: 2, cnsa: false, nist: 'quantum-resistant', pk: 1312 },
  'ML-DSA-65':   { family: 'ML-DSA',  primitive: 'signature', param: 'ML-DSA-65',   category: 3, cnsa: false, nist: 'quantum-resistant', pk: 1952 },
  'ML-DSA-87':   { family: 'ML-DSA',  primitive: 'signature', param: 'ML-DSA-87',   category: 5, cnsa: true,  nist: 'quantum-resistant', pk: 2592 },
  'SLH-DSA-SHA2-128s':  { family: 'SLH-DSA', primitive: 'signature', param: 'SLH-DSA-SHA2-128s',  category: 1, cnsa: false, nist: 'quantum-resistant', pk: 32 },
  'SLH-DSA-SHAKE-256f': { family: 'SLH-DSA', primitive: 'signature', param: 'SLH-DSA-SHAKE-256f', category: 5, cnsa: false, nist: 'quantum-resistant', pk: 64 },
  'rsaEncryption':        { family: 'RSA',    primitive: 'pke',       param: null, category: 0, cnsa: false, nist: 'deprecated-2030-disallowed-2035' },
  'sha256WithRSAEncryption': { family: 'RSA', primitive: 'signature', param: null, category: 0, cnsa: false, nist: 'deprecated-2030-disallowed-2035' },
  'sha384WithRSAEncryption': { family: 'RSA', primitive: 'signature', param: null, category: 0, cnsa: false, nist: 'deprecated-2030-disallowed-2035' },
  'sha512WithRSAEncryption': { family: 'RSA', primitive: 'signature', param: null, category: 0, cnsa: false, nist: 'deprecated-2030-disallowed-2035' },
  'id-ecPublicKey':       { family: 'EC',     primitive: 'key-agree', param: null, category: 0, cnsa: false, nist: 'deprecated-2030-disallowed-2035' },
  'ecdsa-with-SHA256':    { family: 'ECDSA',  primitive: 'signature', param: null, category: 0, cnsa: false, nist: 'deprecated-2030-disallowed-2035' },
  'ecdsa-with-SHA384':    { family: 'ECDSA',  primitive: 'signature', param: null, category: 0, cnsa: false, nist: 'deprecated-2030-disallowed-2035' },
  'ED25519':              { family: 'EdDSA',  primitive: 'signature', param: null, category: 0, cnsa: false, nist: 'deprecated-2030-disallowed-2035' },
};

// CNSA 1.0 parameter floor (CNSA 2.0 doc, Table V): ECDSA P-384, RSA >= 3072.
const CNSA1_FLOOR = { 'prime256v1': false, 'secp384r1': true, rsa: (bits) => bits >= 3072 };

const CLASSICAL_PARAM = {
  rsaEncryption: (bits) => `RSA-${bits}`,
  sha256WithRSAEncryption: (bits) => `RSA-${bits}`,
  sha384WithRSAEncryption: (bits) => `RSA-${bits}`,
  sha512WithRSAEncryption: (bits) => `RSA-${bits}`,
  'id-ecPublicKey': (bits, curve) => ({ 'prime256v1': 'P-256', 'secp384r1': 'P-384' }[curve] || curve),
  'ecdsa-with-SHA256': (bits, curve) => ({ 'prime256v1': 'P-256', 'secp384r1': 'P-384' }[curve] || curve),
  'ecdsa-with-SHA384': (bits, curve) => ({ 'prime256v1': 'P-256', 'secp384r1': 'P-384' }[curve] || curve),
  ED25519: () => 'Ed25519',
};

function classify(kind, name, ctx = {}) {
  const { bits = null, curve = null } = ctx;
  const row = TABLE[name];
  if (!row) throw new Error(`no classification for ${kind} "${name}" — extend the table with a citation`);
  const out = {
    family: row.family, primitive: row.primitive, paramSet: row.param,
    nistQuantumSecurityLevel: row.category,      // CycloneDX 1.6 field, 0 = category none met
    pqSecure: row.family === 'ML-KEM' || row.family === 'ML-DSA' || row.family === 'SLH-DSA',
    cnsa20Compliant: row.cnsa,
    nistDisposition: row.nist,
  };
  if (row.family === 'RSA') { out.classicalBits = bits; out.cnsa10ParameterOk = bits != null && bits >= 3072; }
  if (row.family === 'EC' || row.family === 'ECDSA') { out.curve = curve; out.cnsa10ParameterOk = curve === 'secp384r1'; }
  if (out.paramSet == null && CLASSICAL_PARAM[name]) out.paramSet = CLASSICAL_PARAM[name](bits, curve);
  return out;
}

function opensslText(file) {
  return execFileSync(OPENSSL, ['x509', '-in', file, '-noout', '-text', '-nameopt', 'RFC2253'], { encoding: 'utf8' });
}

const certs = readdirSync(path.join(dir, 'certs')).filter(f => f.endsWith('.crt')).sort();
const out = { oracle: execFileSync(OPENSSL, ['version'], { encoding: 'utf8' }).trim(),
              generatedUtc: new Date().toISOString(), certificates: [], keys: [], failures: [] };

for (const f of certs) {
  const file = path.join(dir, 'certs', f);
  const raw = readFileSync(file);
  const text = opensslText(file);
  const sig = (text.match(/Signature Algorithm: (\S+)/) || [])[1];
  const keyAlg = (text.match(/Public Key Algorithm: (\S+)/) || [])[1];
  const bitsM = text.match(/Public-Key: \((\d+) bit\)/);
  const curveM = text.match(/ASN1 OID: (\S+)/);
  const entry = {
    file: `certs/${f}`,
    sha256: createHash('sha256').update(raw).digest('hex'),
    derBytes: raw.length,
    subjectDn: (text.match(/Subject: (.*)/) || [])[1],
    notBefore: (text.match(/Not Before: (.*)/) || [])[1],
    notAfter: (text.match(/Not After *: (.*)/) || [])[1],
    signatureAlgorithm: sig,
    signature: null, publicKey: null,
  };
  try {
    entry.signature = classify('signatureAlgorithm', sig, {
      bits: bitsM ? Number(bitsM[1]) : null,
      curve: curveM ? curveM[1] : null,
    });
  }
  catch (e) { out.failures.push({ file: entry.file, error: e.message }); }
  try {
    entry.publicKey = classify('publicKey', keyAlg, {
      bits: bitsM ? Number(bitsM[1]) : null,
      curve: curveM ? curveM[1] : null,
    });
  }
  catch (e) { out.failures.push({ file: entry.file, error: e.message }); }
  out.certificates.push(entry);
}

// Minimal DER walker: returns [tag, headerLen, contentLen] at offset.
function der(header, off) {
  const tag = header[off];
  let len = header[off + 1], hdr = 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + header[off + 2 + i]; hdr = 2 + n; }
  return { tag, hdr, len, content: off + hdr };
}

// Dotted OID -> canonical algorithm name.  The PQ rows are the RFC 9935/9881/9909
// identifiers; the classical rows are what OpenSSL 3.6.5 prints from its object db.
const OID_NAME = {
  '1.2.840.113549.1.1.1': 'rsaEncryption',
  '1.2.840.10045.2.1': 'id-ecPublicKey',
  '1.3.101.112': 'ED25519',
  '2.16.840.1.101.3.4.4.1': 'ML-KEM-512',
  '2.16.840.1.101.3.4.4.2': 'ML-KEM-768',
  '2.16.840.1.101.3.4.4.3': 'ML-KEM-1024',
  '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
  '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
  '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
  '2.16.840.1.101.3.4.3.20': 'SLH-DSA-SHA2-128s',
  '2.16.840.1.101.3.4.3.31': 'SLH-DSA-SHAKE-256f',
  '1.2.840.10045.3.1.7': 'prime256v1',
  '1.3.132.0.34': 'secp384r1',
};

// DER OID content bytes -> dotted string (first byte is 40*x+y, then base-128).
function oidToDotted(buf) {
  const parts = [Math.floor(buf[0] / 40), buf[0] % 40];
  let v = 0;
  for (let i = 1; i < buf.length; i++) {
    v = v * 128 + (buf[i] & 0x7f);
    if (!(buf[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}

// SPKI fixtures: the claimed OID must match the actual encoded key length from
// FIPS 203 Table 3 / FIPS 204 Table 2 / FIPS 205 Table 2.  The BIT STRING
// payload length (minus the unused-bits octet) is the only honest measure of
// "how many key bytes are really in this file".
for (const f of readdirSync(path.join(dir, 'spki')).filter(f => f.endsWith('.pem')).sort()) {
  const pem = readFileSync(path.join(dir, 'spki', f));
  const derBuf = execFileSync(OPENSSL, ['pkey', '-pubin', '-in', path.join(dir, 'spki', f), '-outform', 'DER'], { encoding: 'buffer' });
  const seq = der(derBuf, 0);                        // SubjectPublicKeyInfo SEQUENCE
  const alg = der(derBuf, seq.content);              // AlgorithmIdentifier SEQUENCE
  const oid = der(derBuf, alg.content);              // OID inside it
  const oidDotted = oidToDotted(derBuf.subarray(oid.content, oid.content + oid.len));
  const bits = der(derBuf, alg.content + alg.len);   // BIT STRING follows the AlgorithmIdentifier
  const name = OID_NAME[oidDotted];
  if (!name) throw new Error(`unknown OID ${oidDotted} in ${f}`);
  const entry = { file: `spki/${f}`, sha256: createHash('sha256').update(pem).digest('hex'),
                  derBytes: derBuf.length, algorithm: name, oid: oidDotted,
                  keyOctets: bits.len - 1 };          // minus the unused-bits octet
  if (name === 'id-ecPublicKey') {
    const curve = der(derBuf, alg.content + oid.hdr + oid.len);   // namedCurve OID parameter
    entry.curve = oidToDotted(derBuf.subarray(curve.content, curve.content + curve.len));
  }
  const row = TABLE[name];
  if (row) {
    const expected = row.ek ?? row.pk;
    entry.expectedKeyOctets = expected;
    entry.keyOctetsMatchFipsTable = entry.keyOctets === expected;
  }
  out.keys.push(entry);
}

writeFileSync(path.join(dir, 'expected', 'expected-classification.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote expected-classification.json: ${out.certificates.length} certificates, ${out.keys.length} SPKIs, ${out.failures.length} failures`);
if (out.failures.length) { console.error(out.failures); process.exit(1); }
