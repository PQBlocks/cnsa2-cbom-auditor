// lib/fallback.js — Fallback X.509 certificate parser (S-10).
// Wraps @peculiar/x509 (pure-JS, WebCrypto-based) for Node versions that
// lack PQ-aware native certificate parsing (Node < 26). Produces the SAME
// Asset shape as lib/x509.js parseCert — same keys, same Buffer/Date types,
// same parameter-byte semantics — so lib/classify.js and lib/cbom.js consume
// either parser interchangeably.
'use strict';

const { InvalidAssetError, parseDer } = require('./der');

// @peculiar/x509 pulls in tsyringe, which requires reflect-metadata at import
// time. Loaded lazily so callers that only want isFallbackRequired() never
// pay for (or break on) the fallback dependency.
let peculiar = null;
function loadPeculiar() {
  if (peculiar === null) {
    require('reflect-metadata');
    // eslint-disable-next-line global-require
    peculiar = require('@peculiar/x509');
  }
  return peculiar;
}

// Node < 26 lacks PQ X509Certificate support; those runtimes need the
// fallback. Anything unparseable is a hard TypeError — never a silent guess.
function isFallbackRequired(version) {
  if (typeof version !== 'string') {
    throw new TypeError(`isFallbackRequired expects a Node version string like "24.11.1", got ${version === null ? 'null' : typeof version}`);
  }
  const trimmed = version.trim();
  const m = /^v?(\d+)(\.\d+)*$/.exec(trimmed);
  if (!m) {
    throw new TypeError(`isFallbackRequired expects a Node version string like "24.11.1", got "${version}"`);
  }
  return Number(m[1]) < 26;
}

// Native parseCert stores AlgorithmIdentifier.parameters as the raw CONTENT
// bytes of the parameter child node (Buffer), or null when absent.
// @peculiar decodes parameters as: undefined (absent), null (explicit NULL),
// or a raw DER TLV buffer/ArrayBuffer of the parameter value. Normalise to
// the native convention: strip exactly one TLV layer.
function normalizeParameters(params) {
  if (params === undefined) return null; // absent in AlgorithmIdentifier
  if (params === null) return Buffer.alloc(0); // explicit NULL -> empty content
  let buf;
  if (Buffer.isBuffer(params)) {
    buf = params;
  } else if (params instanceof ArrayBuffer) {
    buf = Buffer.from(params);
  } else if (ArrayBuffer.isView(params)) {
    buf = Buffer.from(params.buffer, params.byteOffset, params.byteLength);
  } else {
    throw new InvalidAssetError(`unsupported AlgorithmIdentifier parameters encoding: ${Object.prototype.toString.call(params)}`);
  }
  if (buf.length < 2) return Buffer.alloc(0);
  // Single-byte tag (all AlgorithmIdentifier parameter tags in scope are
  // < 31), then short- or long-form length, then content.
  let off = 1;
  const lenByte = buf[off++];
  let len;
  if (lenByte & 0x80) {
    const n = lenByte & 0x7f;
    if (n === 0 || off + n > buf.length) {
      throw new InvalidAssetError('malformed parameter TLV: bad long-form length');
    }
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off++];
  } else {
    len = lenByte;
  }
  if (off + len > buf.length) {
    throw new InvalidAssetError('malformed parameter TLV: content exceeds buffer');
  }
  return Buffer.from(buf.subarray(off, off + len));
}

// @peculiar Time objects carry utcTime or generalTime — as Date instances.
function decodeTime(time, field) {
  const value = time && (time.utcTime || time.generalTime);
  const date = value instanceof Date ? value : (typeof value === 'string' ? new Date(value) : null);
  if (!date || Number.isNaN(date.getTime())) {
    throw new InvalidAssetError(`fallback parser: missing ${field} time`);
  }
  return date;
}

function asBuffer(bytes, what) {
  if (bytes === undefined || bytes === null) {
    throw new InvalidAssetError(`fallback parser: missing ${what}`);
  }
  if (Buffer.isBuffer(bytes)) return Buffer.from(bytes);
  if (bytes instanceof ArrayBuffer) return Buffer.from(bytes);
  if (ArrayBuffer.isView(bytes)) return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  throw new InvalidAssetError(`fallback parser: unexpected ${what} encoding`);
}

function algorithmIdentifier(alg, what) {
  if (!alg || typeof alg.algorithm !== 'string' || alg.algorithm.length === 0) {
    throw new InvalidAssetError(`fallback parser: missing ${what} OID`);
  }
  return { oid: alg.algorithm, parameters: normalizeParameters(alg.parameters) };
}

function parseCertFallback(der) {
  // DER bytes only. PEM text must go through the PEM layer first (same
  // contract as the native parser: a PEM string is not DER and must throw).
  if (!Buffer.isBuffer(der) && !ArrayBuffer.isView(der) && !(der instanceof ArrayBuffer)) {
    throw new InvalidAssetError(`fallback parser expects a DER Buffer, got ${der === null ? 'null' : typeof der}`);
  }
  const buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  if (buf.length === 0) {
    throw new InvalidAssetError('fallback parser: empty input');
  }
  // DER gate: reject non-DER bytes (e.g. PEM text) exactly like the native
  // parser — @peculiar/x509 would otherwise sniff and accept PEM.
  parseDer(buf);

  const { X509Certificate } = loadPeculiar();
  let cert;
  try {
    cert = new X509Certificate(buf);
  } catch (err) {
    throw new InvalidAssetError(`fallback parser could not parse certificate: ${err && err.message ? err.message : err}`);
  }

  const asn = cert.asn;
  const tbs = asn && asn.tbsCertificate;
  if (!asn || !tbs) {
    throw new InvalidAssetError('fallback parser: @peculiar/x509 returned no TBSCertificate');
  }

  const version = (typeof tbs.version === 'number' ? tbs.version : 0) + 1; // ASN.1 v3 == 2 -> Asset version 3
  const serialNumber = asBuffer(tbs.serialNumber, 'serialNumber');
  const signatureAlgorithm = algorithmIdentifier(asn.signatureAlgorithm, 'signatureAlgorithm');
  const tbsSignatureAlgorithm = algorithmIdentifier(tbs.signature, 'tbs signatureAlgorithm');

  const spki = tbs.subjectPublicKeyInfo;
  if (!spki || !spki.algorithm) {
    throw new InvalidAssetError('fallback parser: missing subjectPublicKeyInfo');
  }
  const spkiAlg = algorithmIdentifier(spki.algorithm, 'subjectPublicKeyInfo');
  const keyBytes = asBuffer(spki.subjectPublicKey, 'subjectPublicKey');

  return {
    type: 'certificate',
    version,
    serialNumber,
    der: buf,
    signatureAlgorithm,
    tbsSignatureAlgorithm,
    subjectPublicKeyInfo: {
      oid: spkiAlg.oid,
      keyBytes,
      parameters: spkiAlg.parameters,
    },
    keyBytes: Buffer.from(keyBytes),
    notBefore: decodeTime(tbs.validity && tbs.validity.notBefore, 'notBefore'),
    notAfter: decodeTime(tbs.validity && tbs.validity.notAfter, 'notAfter'),
    subjectDn: cert.subject,
    issuerDn: cert.issuer,
  };
}

// _internals is exposed solely so the slice's tests can drive the defensive
// branches with hostile inputs; it is not part of the public API surface.
module.exports = { parseCertFallback, isFallbackRequired, InvalidAssetError, _internals: { normalizeParameters, decodeTime, asBuffer, algorithmIdentifier } };
