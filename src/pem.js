// lib/pem.js — slice S-11: PEM multi-block + PKCS#7/PKCS#12 bundle handling.
//
// Contract (spec/spec.md S-11):
//   splitPemBlocks(text) -> string[]
//   PKCS#7 / PKCS#12 detection via the ContentInfo OID
//   unwrap a PKCS#7 SignedData bundle to the certificates it carries
//
// Design notes:
//   * Low-level extractors throw InvalidAssetError on hostile input (a caller
//     that asked for "the certs in this bundle" must learn it was not one).
//     analyzePemBlocks never throws per block: it records `error` on the block
//     result and keeps scanning, because a scan target may mix good and broken
//     files.
//   * PKCS#12 is exported encrypted in practice; without the passphrase the
//     certificates are not recoverable, so it is reported as `pkcs12` with no
//     certs and a reason. We never attempt to decrypt a user bundle.
//   * The DER walker is lib/der.js (S-02): bounded depth, no indefinite
//     lengths, 10 MB cap. This module only navigates the parsed tree and
//     re-serialises canonical DER (tag + length + content), which is
//     byte-identical for DER input.

'use strict';

const { parseDer, InvalidAssetError } = require('./der');

const PKCS7_OID = '1.2.840.113549.1.7.2'; // signedData
const PKCS12_OID = '1.2.840.113549.1.12.1'; // pfx
const PKCS12_BAG_PREFIX = '1.2.840.113549.1.12.10.1'; // keyBag / shroudedKeyBag / certBag / ...

const PEM_BLOCK_RE = /-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\s]+?)-----END \1-----/g;
const PEM_LABEL_RE = /-----BEGIN ([A-Z0-9 ]+)-----/;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

// --- PEM splitting ---------------------------------------------------------

/**
 * Split PEM text into the individual PEM block strings it contains.
 * Line endings are normalised to LF; text outside blocks is ignored; an
 * unterminated BEGIN marker yields no block (it is not a complete block).
 *
 * @param {string} text
 * @returns {string[]}
 */
function splitPemBlocks(text) {
  if (typeof text !== 'string') {
    throw new TypeError(`splitPemBlocks expects a string, got ${typeof text}`);
  }
  const normalised = text.replace(/\r\n?/g, '\n');
  const blocks = [];
  PEM_BLOCK_RE.lastIndex = 0;
  let match;
  while ((match = PEM_BLOCK_RE.exec(normalised)) !== null) {
    blocks.push(match[0].trim());
  }
  return blocks;
}

// --- Label detection -------------------------------------------------------

/**
 * Map a PEM label to a coarse asset type.
 * @param {string} label - text between -----BEGIN and -----
 * @returns {'certificate'|'publicKey'|'privateKey'|'pkcs7'|'pkcs12'|'csr'|'unknown'}
 */
function detectPemType(label) {
  if (typeof label !== 'string') {
    throw new TypeError(`detectPemType expects a string, got ${typeof label}`);
  }
  const upper = label.toUpperCase().trim();
  if (upper === 'CERTIFICATE' || upper === 'X509 CERTIFICATE' || upper === 'TRUSTED CERTIFICATE') {
    return 'certificate';
  }
  if (upper === 'PUBLIC KEY') {
    return 'publicKey';
  }
  if (upper === 'PRIVATE KEY' || upper === 'RSA PRIVATE KEY' || upper === 'EC PRIVATE KEY'
      || upper === 'ENCRYPTED PRIVATE KEY') {
    return 'privateKey';
  }
  if (upper === 'PKCS7' || upper === 'PKCS#7') {
    return 'pkcs7';
  }
  if (upper === 'PKCS12' || upper === 'PKCS#12') {
    return 'pkcs12';
  }
  if (upper === 'CERTIFICATE REQUEST' || upper === 'CSR') {
    return 'csr';
  }
  return 'unknown';
}

// --- DER helpers -----------------------------------------------------------

function decodeOid(buf) {
  if (buf.length === 0) throw new InvalidAssetError('empty OID');
  const first = buf[0];
  const firstArc = first < 80 ? Math.floor(first / 40) : 2;
  const arcs = [firstArc, first - firstArc * 40];
  let value = 0;
  let inArc = false;
  for (let i = 1; i < buf.length; i++) {
    const b = buf[i];
    value = (value << 7) | (b & 0x7f);
    inArc = (b & 0x80) !== 0;
    if (!inArc) {
      arcs.push(value);
      value = 0;
    }
  }
  if (inArc) throw new InvalidAssetError('truncated OID arc');
  return arcs.join('.');
}

function encodeLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let rest = n;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function encodeDer(node) {
  let content;
  if (node.constructed && Array.isArray(node.children)) {
    content = Buffer.concat(node.children.map(encodeDer));
  } else {
    content = node.content;
  }
  return Buffer.concat([Buffer.from([node.tag]), encodeLength(content.length), content]);
}

/**
 * Decode a PEM block or bare base64 string to DER bytes. A Buffer is already
 * DER and is returned unchanged.
 * @param {string|Buffer} input
 * @returns {Buffer}
 */
function toDer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (typeof input !== 'string') {
    throw new InvalidAssetError(`expected a PEM string or DER Buffer, got ${typeof input}`);
  }
  let body = input;
  const labelMatch = input.match(PEM_LABEL_RE);
  if (labelMatch) {
    const endMarker = `-----END ${labelMatch[1]}-----`;
    const endIdx = input.indexOf(endMarker);
    if (endIdx === -1) throw new InvalidAssetError(`missing ${endMarker}`);
    body = input.slice(input.indexOf(labelMatch[0]) + labelMatch[0].length, endIdx);
  }
  const compact = body.replace(/\s+/g, '');
  if (compact.length === 0 || compact.length % 4 !== 0 || !BASE64_RE.test(compact)) {
    throw new InvalidAssetError('PEM body is not valid base64');
  }
  const der = Buffer.from(compact, 'base64');
  if (der.length === 0) throw new InvalidAssetError('PEM body decodes to zero bytes');
  return der;
}

function contentInfoOidFrom(root) {
  if (root.tag !== 0x30 || !root.children) return null;
  // ContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER, content [0] ... }
  if (root.children[0] && root.children[0].tag === 0x06) {
    return decodeOid(root.children[0].content);
  }
  // PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData OPTIONAL }
  // (RFC 7292 §4) — the ContentInfo carrying the PKCS#12 OID sits one level in.
  if (root.children[0] && root.children[0].tag === 0x02 && root.children[1] && root.children[1].tag === 0x30) {
    const inner = root.children[1].children && root.children[1].children[0];
    if (inner && inner.tag === 0x06) return decodeOid(inner.content);
  }
  return null;
}

function contentInfoOid(der) {
  const oid = contentInfoOidFrom(parseDer(Buffer.isBuffer(der) ? der : Buffer.from(der)));
  if (oid === null) {
    throw new InvalidAssetError('not an ASN.1 ContentInfo SEQUENCE');
  }
  return oid;
}

// --- OID detection ---------------------------------------------------------

function findOidInTree(node, predicate, depth) {
  if (depth > 12) return false;
  if (node.tag === 0x06) {
    try {
      if (predicate(decodeOid(node.content))) return true;
    } catch {
      // an undecodable OID is not a bundle marker
    }
  }
  // An OCTET STRING can wrap another DER structure: the PFX AuthenticatedSafe
  // is carried inside authSafe's [0] EXPLICIT OCTET STRING.
  if (node.tag === 0x04) {
    try {
      if (findOidInTree(parseDer(node.content), predicate, depth + 1)) return true;
    } catch {
      // opaque payload (e.g. encrypted bytes) — nothing to inspect
    }
  }
  for (const child of node.children || []) {
    if (findOidInTree(child, predicate, depth + 1)) return true;
  }
  return false;
}

/**
 * Detect PKCS#7 / PKCS#12 by OID. Returns null when the DER is a valid ASN.1
 * value that is not one of those bundles (e.g. a bare certificate). Throws
 * InvalidAssetError when it is not DER.
 *
 * A PKCS#7 bundle names itself with the signedData OID at the root
 * ContentInfo. A PKCS#12 PFX is PFX{version INTEGER, authSafe ContentInfo,
 * macData} — its authSafe is a ContentInfo of type `data`, and the real
 * PKCS#12 identity is the bag OIDs (1.2.840.113549.1.12.10.1.x) inside the
 * AuthenticatedSafe, or the pfx OID when a PFX is carried as CMS content.
 *
 * @param {Buffer|string} input - DER bytes, or a PEM/base64 string
 * @returns {'pkcs7'|'pkcs12'|null}
 */
function detectBundleOid(input) {
  const der = toDer(input);
  const root = parseDer(der); // non-DER throws: the caller asked a DER question
  const direct = contentInfoOidFrom(root);
  if (direct === PKCS7_OID) return 'pkcs7';
  if (direct === PKCS12_OID) return 'pkcs12';

  const first = root.children && root.children[0];
  const second = root.children && root.children[1];
  if (first && first.tag === 0x02 && second && second.tag === 0x30) {
    const isPkcs12Bag = (oid) => oid === PKCS12_OID || oid.startsWith(PKCS12_BAG_PREFIX);
    if (findOidInTree(second, isPkcs12Bag, 0)) return 'pkcs12';
  }
  return null;
}

// --- PKCS#7 unwrapping -----------------------------------------------------

/**
 * Extract the certificates carried by a PKCS#7/CMS SignedData bundle.
 *
 * SignedData is ContentInfo{ contentType = signedData,
 *   content [0] EXPLICIT { version, digestAlgorithms, encapContentInfo,
 *   certificates [0] IMPLICIT CertificateSet OPTIONAL, ... } }.
 * Only genuine Certificate SEQUENCEs are returned; attribute certificates and
 * other CertificateChoices are skipped.
 *
 * @param {string|Buffer} input - PKCS#7 PEM block or DER bytes
 * @returns {string[]} certificate PEM blocks (empty when the bundle has none)
 */
function extractCertsFromPkcs7(input) {
  const der = toDer(input);
  const oid = contentInfoOid(der);
  if (oid !== PKCS7_OID) {
    throw new InvalidAssetError(`not a PKCS#7/CMS bundle: ContentInfo OID is ${oid}`);
  }
  const root = parseDer(der);
  const explicit = root.children[1];
  if (!explicit || !explicit.constructed || explicit.tagClass !== 'context-specific' || explicit.tagNumber !== 0) {
    throw new InvalidAssetError('PKCS#7 ContentInfo is missing its [0] EXPLICIT content');
  }
  const signedData = (explicit.children || [])[0];
  if (!signedData || signedData.tag !== 0x30) {
    throw new InvalidAssetError('PKCS#7 content is not a SignedData SEQUENCE');
  }

  const certSet = (signedData.children || []).find(
    (child) => child.constructed && child.tagClass === 'context-specific' && child.tagNumber === 0,
  );
  if (!certSet || !certSet.children) return [];

  const certs = [];
  for (const choice of certSet.children) {
    if (choice.tag === 0x30 && choice.tagClass === 'universal' && choice.constructed) {
      const body = encodeDer(choice).toString('base64');
      const wrapped = body.match(/.{1,64}/g).join('\n');
      certs.push(`-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`);
    }
  }
  return certs;
}

// --- Aggregate analysis ----------------------------------------------------

/**
 * Split PEM text, classify every block, and unwrap PKCS#7 bundles.
 * Block-level failures are reported on the result (`error`) instead of
 * aborting the whole file, so one corrupt block cannot hide the rest.
 *
 * @param {string} text
 * @returns {{blocks: string[], results: Array<{block: string, label: string|null,
 *   type: string, certs: string[], error?: string, reason?: string}>}}
 */
function analyzePemBlocks(text) {
  if (typeof text !== 'string') {
    throw new TypeError(`analyzePemBlocks expects a string, got ${typeof text}`);
  }
  const blocks = splitPemBlocks(text);
  const results = [];

  for (const block of blocks) {
    const labelMatch = block.match(PEM_LABEL_RE);
    const label = labelMatch ? labelMatch[1] : null;
    const labelType = label === null ? 'unknown' : detectPemType(label);
    const result = { block, label, type: labelType, certs: [] };

    let der;
    try {
      der = toDer(block);
    } catch (err) {
      result.error = err.message;
      results.push(result);
      continue;
    }

    let oidType = null;
    try {
      oidType = detectBundleOid(der);
    } catch (err) {
      result.error = err.message;
      results.push(result);
      continue;
    }
    if (oidType !== null) result.type = oidType;

    try {
      if (result.type === 'pkcs7') {
        result.certs = extractCertsFromPkcs7(der);
      } else if (result.type === 'pkcs12') {
        result.reason = 'encrypted or passphrase-protected PKCS#12 bundle; certificates are not '
          + 'extractable without the export passphrase';
      } else if (result.type === 'certificate') {
        // Validate the body is a certificate-shaped DER object before
        // handing it on; a truncated certificate must not look like an asset.
        parseDer(der);
        result.certs = [block];
      }
    } catch (err) {
      result.error = err.message;
      result.certs = [];
    }

    results.push(result);
  }

  return { blocks, results };
}

module.exports = {
  splitPemBlocks,
  detectPemType,
  detectBundleOid,
  extractCertsFromPkcs7,
  analyzePemBlocks,
  PKCS7_OID,
  PKCS12_OID,
};
