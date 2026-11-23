// lib/constants.js — OID registry constants (slice S-01).
//
// Sources (no runtime configuration; every value is transcribed from a primary):
//   - OID_TABLE rows: golden-vectors/oid-classification.json (itself transcribed
//     from RFC 9935 §3, RFC 9881 §3, RFC 9909 §3; sources per row). Do not edit
//     a row without re-fetching its source.
//   - CLASSICAL_OIDS: brief/research-brief.md §3.1 "Classical OIDs the auditor
//     must also recognise"; classification rows from the same golden vector;
//     IR 8547 status from brief §2.4 (Tables 2 and 4).
//   - PARAMETER_SETS: brief/research-brief.md §2.1 (FIPS 203 Table 2/3),
//     §2.2 (FIPS 204 Table 2), §2.3 (FIPS 205 Table 2).
//
// CNSA 2.0 (PP-22-1338, Table III/IV) requires Level V for public-key
// algorithms: only ML-KEM-1024 and ML-DSA-87 are cnsa2Compliant. SLH-DSA is
// PQ-approved per NIST IR 8547 but is NOT listed by CNSA 2.0, so all SLH-DSA
// sets carry cnsa2Compliant: false.

'use strict';

function deepFreeze(obj) {
  if (obj && typeof obj === 'object' && !Object.isFrozen(obj)) {
    for (const value of Object.values(obj)) deepFreeze(value);
    Object.freeze(obj);
  }
  return obj;
}

// --- OID_TABLE: 18 PQ OIDs, values byte-for-byte identical to the golden ------
// --- vector's classifications rows for these OIDs (see tests/). ----------------
const OID_TABLE = deepFreeze({
  '2.16.840.1.101.3.4.4.1': { oid: '2.16.840.1.101.3.4.4.1', name: 'id-alg-ml-kem-512', primitive: 'kem', parameterSetIdentifier: 'ML-KEM-512', nistQuantumSecurityLevel: 1, cnsa2_status: 'not-required-level', source: 'RFC 9935 Sec 3; FIPS 203 Table 2' },
  '2.16.840.1.101.3.4.4.2': { oid: '2.16.840.1.101.3.4.4.2', name: 'id-alg-ml-kem-768', primitive: 'kem', parameterSetIdentifier: 'ML-KEM-768', nistQuantumSecurityLevel: 3, cnsa2_status: 'not-required-level', source: 'RFC 9935 Sec 3; FIPS 203 Table 2' },
  '2.16.840.1.101.3.4.4.3': { oid: '2.16.840.1.101.3.4.4.3', name: 'id-alg-ml-kem-1024', primitive: 'kem', parameterSetIdentifier: 'ML-KEM-1024', nistQuantumSecurityLevel: 5, cnsa2_status: 'required-level-v', source: 'RFC 9935 Sec 3; FIPS 203 Table 2; CNSA 2.0 Table III (Use Level V)' },
  '2.16.840.1.101.3.4.3.17': { oid: '2.16.840.1.101.3.4.3.17', name: 'id-ml-dsa-44', primitive: 'signature', parameterSetIdentifier: 'ML-DSA-44', nistQuantumSecurityLevel: 2, cnsa2_status: 'not-required-level', source: 'RFC 9881 Sec 3; FIPS 204 Table 2' },
  '2.16.840.1.101.3.4.3.18': { oid: '2.16.840.1.101.3.4.3.18', name: 'id-ml-dsa-65', primitive: 'signature', parameterSetIdentifier: 'ML-DSA-65', nistQuantumSecurityLevel: 3, cnsa2_status: 'not-required-level', source: 'RFC 9881 Sec 3; FIPS 204 Table 2' },
  '2.16.840.1.101.3.4.3.19': { oid: '2.16.840.1.101.3.4.3.19', name: 'id-ml-dsa-87', primitive: 'signature', parameterSetIdentifier: 'ML-DSA-87', nistQuantumSecurityLevel: 5, cnsa2_status: 'required-level-v', source: 'RFC 9881 Sec 3; FIPS 204 Table 2; CNSA 2.0 Table III (Use Level V)' },
  '2.16.840.1.101.3.4.3.20': { oid: '2.16.840.1.101.3.4.3.20', name: 'id-slh-dsa-sha2-128s', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHA2-128s', nistQuantumSecurityLevel: 1, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.21': { oid: '2.16.840.1.101.3.4.3.21', name: 'id-slh-dsa-sha2-128f', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHA2-128f', nistQuantumSecurityLevel: 1, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.22': { oid: '2.16.840.1.101.3.4.3.22', name: 'id-slh-dsa-sha2-192s', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHA2-192s', nistQuantumSecurityLevel: 3, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.23': { oid: '2.16.840.1.101.3.4.3.23', name: 'id-slh-dsa-sha2-192f', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHA2-192f', nistQuantumSecurityLevel: 3, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.24': { oid: '2.16.840.1.101.3.4.3.24', name: 'id-slh-dsa-sha2-256s', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHA2-256s', nistQuantumSecurityLevel: 5, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.25': { oid: '2.16.840.1.101.3.4.3.25', name: 'id-slh-dsa-sha2-256f', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHA2-256f', nistQuantumSecurityLevel: 5, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.26': { oid: '2.16.840.1.101.3.4.3.26', name: 'id-slh-dsa-shake-128s', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHAKE-128s', nistQuantumSecurityLevel: 1, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.27': { oid: '2.16.840.1.101.3.4.3.27', name: 'id-slh-dsa-shake-128f', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHAKE-128f', nistQuantumSecurityLevel: 1, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.28': { oid: '2.16.840.1.101.3.4.3.28', name: 'id-slh-dsa-shake-192s', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHAKE-192s', nistQuantumSecurityLevel: 3, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.29': { oid: '2.16.840.1.101.3.4.3.29', name: 'id-slh-dsa-shake-192f', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHAKE-192f', nistQuantumSecurityLevel: 3, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.30': { oid: '2.16.840.1.101.3.4.3.30', name: 'id-slh-dsa-shake-256s', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHAKE-256s', nistQuantumSecurityLevel: 5, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
  '2.16.840.1.101.3.4.3.31': { oid: '2.16.840.1.101.3.4.3.31', name: 'id-slh-dsa-shake-256f', primitive: 'signature', parameterSetIdentifier: 'SLH-DSA-SHAKE-256f', nistQuantumSecurityLevel: 5, cnsa2_status: 'pq-approved', source: 'RFC 9909 Sec 3; FIPS 205 Table 2' },
});

const LEGACY_STATUS = 'legacy-deprecated-after-2030-disallowed-after-2035';

// --- CLASSICAL_OIDS: the 12 classical OIDs from brief §3.1 ---------------------
// The four rows also present in golden-vectors/oid-classification.json are
// byte-for-byte identical to that vector; the remaining eight carry the same
// record shape, sourced from brief §3.1 / §2.4 (NIST IR 8547 Tables 2 and 4).
// prime256v1 and secp384r1 are namedCurve OIDs, not algorithm primitives:
// primitive is null and a note records their role for the SPKI namedCurve case.
const CLASSICAL_OIDS = deepFreeze({
  '1.2.840.113549.1.1.1': { oid: '1.2.840.113549.1.1.1', name: 'rsaEncryption', primitive: 'pke', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 4 (RSA KE); OID is the PKCS#1 rsaEncryption arc' },
  '1.2.840.113549.1.1.11': { oid: '1.2.840.113549.1.1.11', name: 'sha256WithRSAEncryption', primitive: 'signature', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2 (RSA signatures); OID is the PKCS#1 sha256WithRSAEncryption arc' },
  '1.2.840.113549.1.1.12': { oid: '1.2.840.113549.1.1.12', name: 'sha384WithRSAEncryption', primitive: 'signature', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2 (RSA signatures); OID is the PKCS#1 sha384WithRSAEncryption arc' },
  '1.2.840.113549.1.1.13': { oid: '1.2.840.113549.1.1.13', name: 'sha512WithRSAEncryption', primitive: 'signature', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2 (RSA signatures); OID is the PKCS#1 sha512WithRSAEncryption arc' },
  '1.2.840.113549.1.1.10': { oid: '1.2.840.113549.1.1.10', name: 'RSASSA-PSS', primitive: 'signature', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2 (RSA signatures); OID is the PKCS#1 RSASSA-PSS arc' },
  '1.2.840.10045.2.1': { oid: '1.2.840.10045.2.1', name: 'id-ecPublicKey', primitive: 'key-agree', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 4 (EC DH and MQV); OID is the ANSI X9.62 id-ecPublicKey arc' },
  '1.2.840.10045.3.1.7': { oid: '1.2.840.10045.3.1.7', name: 'prime256v1', primitive: null, parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2/4 (EC ≥112-bit); OID is the ANSI X9.62 prime256v1 namedCurve arc', note: 'namedCurve OID; not an algorithm primitive — recognised for SPKI namedCurve parameters' },
  '1.2.840.10045.4.3.2': { oid: '1.2.840.10045.4.3.2', name: 'ecdsa-with-SHA256', primitive: 'signature', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2 (ECDSA); OID is the ANSI X9.62 ecdsa-with-SHA256 arc' },
  '1.2.840.10045.4.3.3': { oid: '1.2.840.10045.4.3.3', name: 'ecdsa-with-SHA384', primitive: 'signature', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2 (ECDSA); OID is the ANSI X9.62 ecdsa-with-SHA384 arc' },
  '1.3.132.0.34': { oid: '1.3.132.0.34', name: 'secp384r1', primitive: null, parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2/4 (EC ≥112-bit); OID is the SEC 2 secp384r1 namedCurve arc', note: 'namedCurve OID; not an algorithm primitive — recognised for SPKI namedCurve parameters' },
  '1.3.101.112': { oid: '1.3.101.112', name: 'ED25519', primitive: 'signature', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2 (EdDSA); OID is the RFC 8410 Ed25519 arc' },
  '1.3.101.113': { oid: '1.3.101.113', name: 'ED448', primitive: 'signature', parameterSetIdentifier: null, nistQuantumSecurityLevel: 0, cnsa2_status: LEGACY_STATUS, source: 'NIST IR 8547 Table 2 (EdDSA); OID is the RFC 8410 Ed448 arc' },
});

// --- PARAMETER_SETS: FIPS 203/204/205 tables via brief §2 ---------------------
const PARAMETER_SETS = deepFreeze({
  // brief §2.1 — FIPS 203 Table 2 and Table 3 (evidence §1.1)
  'ML-KEM-512': { family: 'ML-KEM', n: 256, q: 3329, k: 2, eta1: 3, eta2: 2, du: 10, dv: 4, ekBytes: 800, dkBytes: 1632, ctBytes: 768, ssBytes: 32, nistCategory: 1, cnsa2Compliant: false },
  'ML-KEM-768': { family: 'ML-KEM', n: 256, q: 3329, k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, ekBytes: 1184, dkBytes: 2400, ctBytes: 1088, ssBytes: 32, nistCategory: 3, cnsa2Compliant: false },
  'ML-KEM-1024': { family: 'ML-KEM', n: 256, q: 3329, k: 4, eta1: 2, eta2: 2, du: 11, dv: 5, ekBytes: 1568, dkBytes: 3168, ctBytes: 1568, ssBytes: 32, nistCategory: 5, cnsa2Compliant: true },

  // brief §2.2 — FIPS 204 Table 2 (evidence §1.2)
  'ML-DSA-44': { family: 'ML-DSA', privateKeyBytes: 2560, publicKeyBytes: 1312, signatureBytes: 2420, nistCategory: 2, cnsa2Compliant: false, note: 'category 2 (1 with a <192-bit RBG, IR 8547 Table 3 note 2)' },
  'ML-DSA-65': { family: 'ML-DSA', privateKeyBytes: 4032, publicKeyBytes: 1952, signatureBytes: 3309, nistCategory: 3, cnsa2Compliant: false },
  'ML-DSA-87': { family: 'ML-DSA', privateKeyBytes: 4896, publicKeyBytes: 2592, signatureBytes: 4627, nistCategory: 5, cnsa2Compliant: true },

  // brief §2.3 — FIPS 205 Table 2 (evidence §1.3); 6 shapes x {SHA2, SHAKE}.
  // CNSA 2.0 does not list SLH-DSA (Table IV lists only Kyber/Dilithium, LMS,
  // XMSS), so every SLH-DSA set is PQ-approved but NOT CNSA 2.0 compliant.
  'SLH-DSA-SHA2-128s': { family: 'SLH-DSA', hash: 'SHA2', shape: '128s', n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, lgw: 4, m: 30, category: 1, pkBytes: 32, sigBytes: 7856, cnsa2Compliant: false },
  'SLH-DSA-SHA2-128f': { family: 'SLH-DSA', hash: 'SHA2', shape: '128f', n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, lgw: 4, m: 34, category: 1, pkBytes: 32, sigBytes: 17088, cnsa2Compliant: false },
  'SLH-DSA-SHA2-192s': { family: 'SLH-DSA', hash: 'SHA2', shape: '192s', n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17, lgw: 4, m: 39, category: 3, pkBytes: 48, sigBytes: 16224, cnsa2Compliant: false },
  'SLH-DSA-SHA2-192f': { family: 'SLH-DSA', hash: 'SHA2', shape: '192f', n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33, lgw: 4, m: 42, category: 3, pkBytes: 48, sigBytes: 35664, cnsa2Compliant: false },
  'SLH-DSA-SHA2-256s': { family: 'SLH-DSA', hash: 'SHA2', shape: '256s', n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, lgw: 4, m: 47, category: 5, pkBytes: 64, sigBytes: 29792, cnsa2Compliant: false },
  'SLH-DSA-SHA2-256f': { family: 'SLH-DSA', hash: 'SHA2', shape: '256f', n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35, lgw: 4, m: 49, category: 5, pkBytes: 64, sigBytes: 49856, cnsa2Compliant: false },
  'SLH-DSA-SHAKE-128s': { family: 'SLH-DSA', hash: 'SHAKE', shape: '128s', n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, lgw: 4, m: 30, category: 1, pkBytes: 32, sigBytes: 7856, cnsa2Compliant: false },
  'SLH-DSA-SHAKE-128f': { family: 'SLH-DSA', hash: 'SHAKE', shape: '128f', n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33, lgw: 4, m: 34, category: 1, pkBytes: 32, sigBytes: 17088, cnsa2Compliant: false },
  'SLH-DSA-SHAKE-192s': { family: 'SLH-DSA', hash: 'SHAKE', shape: '192s', n: 24, h: 63, d: 7, hp: 9, a: 14, k: 17, lgw: 4, m: 39, category: 3, pkBytes: 48, sigBytes: 16224, cnsa2Compliant: false },
  'SLH-DSA-SHAKE-192f': { family: 'SLH-DSA', hash: 'SHAKE', shape: '192f', n: 24, h: 66, d: 22, hp: 3, a: 8, k: 33, lgw: 4, m: 42, category: 3, pkBytes: 48, sigBytes: 35664, cnsa2Compliant: false },
  'SLH-DSA-SHAKE-256s': { family: 'SLH-DSA', hash: 'SHAKE', shape: '256s', n: 32, h: 64, d: 8, hp: 8, a: 14, k: 22, lgw: 4, m: 47, category: 5, pkBytes: 64, sigBytes: 29792, cnsa2Compliant: false },
  'SLH-DSA-SHAKE-256f': { family: 'SLH-DSA', hash: 'SHAKE', shape: '256f', n: 32, h: 68, d: 17, hp: 4, a: 9, k: 35, lgw: 4, m: 49, category: 5, pkBytes: 64, sigBytes: 49856, cnsa2Compliant: false },
});

module.exports = { OID_TABLE, CLASSICAL_OIDS, PARAMETER_SETS };
