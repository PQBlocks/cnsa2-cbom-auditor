// lib/classify.js — slice S-06: Classification engine.
//
// classifyAsset(asset) -> Classification, implementing the decision DAG from
// brief/research-brief.md §2.5:
//
//   family, set   = registry lookup by OID (never by key length — brief P1)
//   pq            = family in {ML-KEM, ML-DSA, SLH-DSA}
//   cnsa          = pq and the OID meets CNSA 2.0 Level V (ML-KEM-1024 / ML-DSA-87)
//   verdict       = compliant | deprecated | disallowed | unknown
//   deadline      = EARLIEST applicable (IR 8547 deprecation 2030-12-31 /
//                   disallowance 2035-12-31, OMB M-26-15 2030-12-31 key establishment)
//
// Verdict mapping (decision recorded in the S-06 session report; only mapping
// that makes no false statement about the sources):
//   - 'compliant'  requires cnsa == true (brief §2.5, not negotiable).
//   - 'deprecated' for the quantum-vulnerable classical families: NIST IR 8547
//     Tables 2/4 deprecate them after 2030 and disallow them after 2035, so
//     today they are deprecated — the registry's legacy status field.
//   - 'disallowed' for any known OID that does not meet the CNSA 2.0 mandate:
//     PQ sets below Level V (ML-KEM-512/768, ML-DSA-44/65) and SLH-DSA in all
//     12 sets (CNSA 2.0 Table IV lists only Kyber/Dilithium Level V plus
//     LMS/XMSS for firmware). IR 8547 never deprecates these PQ algorithms —
//     they are the replacements — so 'deprecated' would be a false statement.
//   - 'unknown' for OIDs absent from the registry; the raw OID is carried in
//     the result and nistQuantumSecurityLevel is omitted (brief P2/EC-08:
//     writing 0 would tell the customer the asset is quantum-vulnerable when
//     it was merely unreadable).
//
// Accepts the Asset shapes the lane's own parsers return:
//   - lib/x509.js parseCert: { type:'certificate', signatureAlgorithm:{oid,parameters},
//     subjectPublicKeyInfo:{oid,keyBytes,parameters}, notBefore, notAfter, ... }
//     -> the certificate is classified by its signatureAlgorithm OID (that is
//     the block the golden oracle classifies); the embedded key is classified
//     separately by passing it as a key asset (brief P3: two verdicts).
//   - lib/spki.js parseSpki: { oid, keyBytes, family, paramSet }
//   - lib/pkcs8.js parsePrivateKey: { oid, format, paramSet }

'use strict';

const { OID_TABLE, CLASSICAL_OIDS, PARAMETER_SETS } = require('./constants');
const { InvalidAssetError } = require('./der');

const LEGACY_STATUS = 'legacy-deprecated-after-2030-disallowed-after-2035';

// IR 8547 Tables 2/4 + OMB M-26-15: quantum-vulnerable classical algorithms are
// deprecated after 2030-12-31 and disallowed after 2035-12-31; OMB requires
// quantum-resistant key establishment by 2030-12-31. Earliest applicable = 2030-12-31.
const CLASSICAL_DEADLINE = '2030-12-31';
// PQ algorithms have no IR 8547 decay clock; the CNSA 2.0 category date depends
// on the asset class (firmware signing 2030, browsers/cloud/OS/PKI 2033), which
// a single parsed asset does not carry — that judgement belongs to the findings
// layer (S-13), not to a per-asset classification.
const PQ_DEADLINE = 'N/A';

// Classical family names match the external oracle (golden-vectors/
// derive-expected.mjs): signatures are ECDSA, key-agreement EC, the rest RSA /
// EdDSA. Source: brief §3.1 + the golden vector's publicKey/signature blocks.
const CLASSICAL_FAMILY = {
  '1.2.840.113549.1.1.1': 'RSA',
  '1.2.840.113549.1.1.10': 'RSA',
  '1.2.840.113549.1.1.11': 'RSA',
  '1.2.840.113549.1.1.12': 'RSA',
  '1.2.840.113549.1.1.13': 'RSA',
  '1.2.840.10045.2.1': 'EC',
  '1.2.840.10045.4.3.2': 'ECDSA',
  '1.2.840.10045.4.3.3': 'ECDSA',
  '1.3.101.112': 'EdDSA',
  '1.3.101.113': 'EdDSA',
};

// CNSA 1.0 / classical parameter naming, from the key context (the same
// derivation the external oracle performs — derive-expected.mjs CLASSICAL_PARAM):
// EC namedCurve OID content bytes -> P-256/P-384, EdDSA OID -> Ed25519/Ed448.
const NAMED_CURVE_TO_PARAMSET = {
  '1.2.840.10045.3.1.7': 'P-256', // prime256v1
  '1.3.132.0.34': 'P-384',        // secp384r1
};

function decodeOidValue(buf) {
  if (!buf || buf.length === 0) return null;
  const first = buf[0];
  const arcs = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < buf.length; i++) {
    const b = buf[i];
    value = (value << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  if (buf[buf.length - 1] & 0x80) return null; // truncated arc
  return arcs.join('.');
}

// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
// Classical bit length comes from the modulus content length (leading zero
// byte dropped); the DER TLVs are walked with bounded, minimal parsing.
function rsaBitsFromKeyBytes(keyBytes) {
  if (!keyBytes || keyBytes.length < 4 || keyBytes[0] !== 0x30) return null;
  let off = 1;
  let len = keyBytes[off];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (1 + 1 + n > keyBytes.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + keyBytes[2 + i];
    off = 2 + n;
  } else {
    off = 2;
  }
  if (off >= keyBytes.length || keyBytes[off] !== 0x02) return null;
  off += 1;
  let mlen = keyBytes[off];
  if (mlen & 0x80) {
    const n = mlen & 0x7f;
    off += 1;
    if (off + n > keyBytes.length) return null;
    mlen = 0;
    for (let i = 0; i < n; i++) mlen = mlen * 256 + keyBytes[off + i];
    off += n;
  } else {
    off += 1;
  }
  if (off + mlen > keyBytes.length) return null;
  const contentLen = mlen;
  if (off + contentLen > keyBytes.length) return null;
  const modulusBytes = keyBytes[off] === 0 ? contentLen - 1 : contentLen;
  return modulusBytes > 0 ? modulusBytes * 8 : null;
}

// Parameter-set identifier for a classical algorithm, derived from the key
// context exactly the way the external oracle derives it. Returns null when
// the context does not determine one (e.g. an unsupported curve) — never a
// guessed value.
function classicalParamSet(oid, parameters, keyBytes) {
  if (oid === '1.2.840.10045.2.1') {
    const curveOid = decodeOidValue(parameters);
    return curveOid ? (NAMED_CURVE_TO_PARAMSET[curveOid] || null) : null;
  }
  if (oid === '1.2.840.113549.1.1.1') {
    const bits = rsaBitsFromKeyBytes(keyBytes);
    return bits ? `RSA-${bits}` : null;
  }
  if (oid === '1.3.101.112') return 'Ed25519';
  if (oid === '1.3.101.113') return 'Ed448';
  return null;
}

function normalizeAsset(asset) {
  if (!asset || typeof asset !== 'object' || Array.isArray(asset)) {
    throw new InvalidAssetError(
      `classifyAsset expects a parsed certificate/key asset object, got ${asset === null ? 'null' : typeof asset}`,
    );
  }
  if (asset.signatureAlgorithm) {
    const oid = asset.signatureAlgorithm.oid;
    if (typeof oid !== 'string') {
      throw new InvalidAssetError('certificate asset has a signatureAlgorithm without an oid');
    }
    const spki = asset.subjectPublicKeyInfo || {};
    return {
      primaryOid: oid,
      isKeyOnly: false,
      keyOid: typeof spki.oid === 'string' ? spki.oid : null,
      keyParameters: spki.parameters || null,
      keyBytes: spki.keyBytes || null,
      assetParamSet: null,
    };
  }
  if (typeof asset.oid === 'string') {
    // Key asset: SPKI (lib/spki.js) or PKCS#8 private key (lib/pkcs8.js).
    return {
      primaryOid: asset.oid,
      isKeyOnly: true,
      keyOid: asset.oid,
      keyParameters: asset.parameters || null,
      keyBytes: asset.keyBytes || null,
      assetParamSet: typeof asset.paramSet === 'string' ? asset.paramSet : null,
    };
  }
  throw new InvalidAssetError('asset has no classifiable algorithm OID (need signatureAlgorithm.oid or oid)');
}

/**
 * @typedef {Object} Classification
 * @property {'compliant'|'deprecated'|'disallowed'|'unknown'} verdict
 * @property {boolean} pqSecure
 * @property {boolean} cnsa20Compliant
 * @property {'quantum-resistant'|'deprecated-2030-disallowed-2035'|'unknown'} nistDisposition
 * @property {string} oid - dotted OID of the classified algorithm (raw when unknown, EC-08)
 * @property {string|null} family - ML-KEM | ML-DSA | SLH-DSA | RSA | EC | ECDSA | EdDSA
 * @property {string|null} parameterSetIdentifier - FIPS parameter set (null for unknown)
 * @property {number|undefined} nistQuantumSecurityLevel - 0..5; omitted when unknown (EC-08)
 * @property {string} deadline - earliest applicable deadline, or 'N/A'
 * @property {string} reason - short, citable reason
 */
function classifyAsset(asset) {
  const ctx = normalizeAsset(asset);
  const row = OID_TABLE[ctx.primaryOid] || CLASSICAL_OIDS[ctx.primaryOid];

  if (!row) {
    // Brief §2.5, not negotiable: an OID absent from the table is unknown and
    // the raw OID is emitted. Never guess from key length (brief P1).
    return {
      verdict: 'unknown',
      pqSecure: false,
      cnsa20Compliant: false,
      nistDisposition: 'unknown',
      oid: ctx.primaryOid,
      family: null,
      parameterSetIdentifier: null,
      deadline: 'N/A',
      reason: `Algorithm OID ${ctx.primaryOid} is not in the OID registry; classified unknown, never guessed from key length`,
    };
  }

  const paramSetIdentifier = row.parameterSetIdentifier;
  const isPQ = paramSetIdentifier !== null && Object.prototype.hasOwnProperty.call(PARAMETER_SETS, paramSetIdentifier);
  const cnsa20Compliant = row.cnsa2_status === 'required-level-v';
  const nistQuantumSecurityLevel = row.nistQuantumSecurityLevel;

  let family;
  let parameterSet;
  if (isPQ) {
    family = PARAMETER_SETS[paramSetIdentifier].family;
    parameterSet = paramSetIdentifier;
  } else {
    family = CLASSICAL_FAMILY[ctx.primaryOid] || null;
    parameterSet = ctx.isKeyOnly && ctx.assetParamSet
      ? ctx.assetParamSet
      : classicalParamSet(ctx.keyOid, ctx.keyParameters, ctx.keyBytes);
  }

  const verdict = cnsa20Compliant ? 'compliant' : (row.cnsa2_status === LEGACY_STATUS ? 'deprecated' : 'disallowed');

  let reason;
  if (verdict === 'compliant') {
    reason = `Meets CNSA 2.0 Level V requirement (${paramSetIdentifier})`;
  } else if (verdict === 'deprecated') {
    reason = 'NIST IR 8547 Tables 2/4: deprecated after 2030, disallowed after 2035';
  } else {
    reason = `Does not meet the CNSA 2.0 Level V requirement (cnsa2_status: ${row.cnsa2_status})`;
  }

  return {
    verdict,
    pqSecure: isPQ,
    cnsa20Compliant,
    nistDisposition: isPQ ? 'quantum-resistant' : 'deprecated-2030-disallowed-2035',
    oid: ctx.primaryOid,
    family,
    parameterSetIdentifier: parameterSet,
    nistQuantumSecurityLevel,
    deadline: isPQ ? PQ_DEADLINE : CLASSICAL_DEADLINE,
    reason,
  };
}

module.exports = { classifyAsset };
