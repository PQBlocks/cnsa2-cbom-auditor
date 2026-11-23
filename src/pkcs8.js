// lib/pkcs8.js — slice S-05: PKCS#8 PrivateKeyInfo parser (read-only, no key material emitted).
//
// parsePrivateKey(pemOrDer) -> { oid, format: 'seed'|'expanded'|'both', paramSet }
// Never emits private key material. Rejects unknown OIDs, malformed structures, and bad input.

'use strict';

const { parseDer, InvalidAssetError } = require('./der.js');
const { OID_TABLE, CLASSICAL_OIDS } = require('./constants.js');

// Combined OID lookup table (PQ + classical).
const ALL_OIDS = { ...OID_TABLE, ...CLASSICAL_OIDS };

// Decode DER-encoded OID content bytes to a dotted-decimal string.
// X.690 §8.19: the FIRST subidentifier encodes (arc0 * 40) + arc1, where arc0 is
// 0, 1 or 2 (so a first value < 40 means arc0=0, < 80 means arc0=1, otherwise
// arc0=2). Every later arc is base-128 with the high bit as continuation.
//
// The previous revision treated the first varint as a standalone arc0 whenever it
// exceeded 2, so the legal ML-KEM OID 2.16.840.1.101.3.4.4.1 decoded as
// "96.840.1.101.3.4.4.1" and was rejected as unknown. That branch was simply wrong.
function decodeOid(bytes) {
  if (bytes.length === 0) {
    throw new InvalidAssetError('empty OID');
  }

  const arcs = [];

  let i = 0;
  let value = 0;
  let byte;

  // First subidentifier: combined arc0 * 40 + arc1.
  do {
    if (i >= bytes.length) {
      throw new InvalidAssetError('truncated OID first arc');
    }
    byte = bytes[i++];
    value = (value << 7) | (byte & 0x7f);
  } while (byte & 0x80);

  if (value < 40) {
    arcs.push(0, value);
  } else if (value < 80) {
    arcs.push(1, value - 40);
  } else {
    arcs.push(2, value - 80);
  }

  // Remaining subidentifiers, one base-128 varint each.
  while (i < bytes.length) {
    value = 0;
    do {
      if (i >= bytes.length) {
        throw new InvalidAssetError('truncated OID arc');
      }
      byte = bytes[i++];
      value = (value << 7) | (byte & 0x7f);
    } while (byte & 0x80);
    arcs.push(value);
  }

  return arcs.join('.');
}

// Detect private key format from the first tag of the private key OCTET STRING content.
//   0x80 -> seed (context-specific [0] IMPLICIT OCTET STRING)
//   0x04 -> expanded (OCTET STRING)
//   0x30 -> both (SEQUENCE of seed + expanded)
function detectFormat(privateKeyContent) {
  if (privateKeyContent.length === 0) {
    throw new InvalidAssetError('privateKey OCTET STRING is empty');
  }
  const firstTag = privateKeyContent[0];
  if (firstTag === 0x80) return 'seed';
  if (firstTag === 0x04) return 'expanded';
  if (firstTag === 0x30) return 'both';
  throw new InvalidAssetError(`unrecognized private key format tag: 0x${firstTag.toString(16)}`);
}

function parsePrivateKey(input) {
  // Reject non-Buffer/string input.
  if (!Buffer.isBuffer(input) && typeof input !== 'string') {
    throw new InvalidAssetError('input must be a Buffer or PEM string');
  }

  // Handle PEM input.
  let derBytes;
  if (typeof input === 'string') {
    const pemMatch = input.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/);
    if (!pemMatch) {
      throw new InvalidAssetError('input must be a DER Buffer or PEM-encoded PRIVATE KEY');
    }
    const pemBlock = pemMatch[0];
    const body = pemBlock.split(/\r?\n/).filter((l) => l && !l.startsWith('-----')).join('');
    derBytes = Buffer.from(body, 'base64');
  } else {
    derBytes = input;
  }

  if (derBytes.length === 0) {
    throw new InvalidAssetError('empty input');
  }

  // Parse DER structure.
  const ast = parseDer(derBytes);

  // Outer must be a constructed SEQUENCE (PrivateKeyInfo).
  if (ast.tag !== 0x30 || !ast.constructed) {
    throw new InvalidAssetError('PKCS#8 PrivateKeyInfo must be a SEQUENCE');
  }

  const children = ast.children || [];
  if (children.length < 3) {
    throw new InvalidAssetError('PKCS#8 PrivateKeyInfo missing required fields');
  }

  // Child 0: version (INTEGER) — accepted, not validated (v1/v2 both allowed).
  // Child 1: privateKeyAlgorithm (AlgorithmIdentifier SEQUENCE).
  // Child 2: privateKey (OCTET STRING).
  const algIdChild = children[1];
  const privateKeyChild = children[2];

  if (algIdChild.tag !== 0x30 || !algIdChild.constructed) {
    throw new InvalidAssetError('privateKeyAlgorithm must be a SEQUENCE');
  }

  const algIdChildren = algIdChild.children || [];
  const oidChild = algIdChildren.find((c) => c.tag === 0x06);
  if (!oidChild) {
    throw new InvalidAssetError('privateKeyAlgorithm missing OID');
  }

  const oid = decodeOid(oidChild.content);

  const oidEntry = ALL_OIDS[oid];
  if (!oidEntry) {
    throw new InvalidAssetError(`unknown algorithm OID: ${oid}`);
  }

  const paramSet = oidEntry.parameterSetIdentifier;

  if (privateKeyChild.tag !== 0x04) {
    throw new InvalidAssetError('privateKey must be an OCTET STRING');
  }

  const format = detectFormat(privateKeyChild.content);

  // Never emit key material.
  return { oid, format, paramSet };
}

module.exports = { parsePrivateKey, InvalidAssetError };
