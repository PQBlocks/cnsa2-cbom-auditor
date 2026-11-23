// lib/der.js — slice S-02: bounded DER walker (no indefinite lengths).
//
// parseDer(bytes) -> AST. A DER TLV is tag + length + content. This parser:
//   * bounds recursion depth at 128 (P10 hardening, RFC 5280 §4.1)
//   * rejects indefinite-length BER encodings (DER prohibits them)
//   * caps declared content length at 10 MB and checks that cap BEFORE any
//     allocation, so an attacker-controlled length can never trigger OOM
//
// Error classes are exported here so the X.509 / SPKI / PKCS#8 slices can
// reuse them; they are also declared in spec/spec.md §4.8.

'use strict';

class InvalidAssetError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidAssetError';
  }
}

class DecompressionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DecompressionError';
  }
}

const MAX_DEPTH = 128;
const MAX_LENGTH = 10 * 1024 * 1024; // 10 MB

const TAG_CLASS = ['universal', 'application', 'context-specific', 'private'];

// Read a DER length at buf[offset]. Returns { length, consumed } where
// consumed is the number of length-encoding bytes (excluding the tag).
function readLength(buf, offset) {
  if (offset >= buf.length) {
    throw new InvalidAssetError('truncated length byte');
  }
  const first = buf[offset];
  if (first === 0x80) {
    // Per spec §1: DecompressionError extends Error { /* indefinite-length BER, etc */ }
    throw new DecompressionError('indefinite-length BER encoding is not DER');
  }
  if (first < 0x80) {
    return { length: first, consumed: 1 };
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0) {
    throw new InvalidAssetError('invalid long-form length (0x80 carries no bytes)');
  }
  if (offset + 1 + numBytes > buf.length) {
    throw new InvalidAssetError('truncated long-form length declaration');
  }
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  if (length > MAX_LENGTH) {
    throw new InvalidAssetError(`declared length ${length} exceeds 10 MB cap`);
  }
  return { length, consumed: 1 + numBytes };
}

// Walk one TLV starting at buf[offset], at the given nesting depth.
// Returns { ast, endOffset } where endOffset is one past the last content byte.
function walkTlvs(buf, offset, depth) {
  if (depth > MAX_DEPTH) {
    throw new InvalidAssetError(`nesting depth exceeds ${MAX_DEPTH}`);
  }
  if (offset >= buf.length) {
    throw new InvalidAssetError('unexpected end of input');
  }
  const tag = buf[offset];
  const tagClass = TAG_CLASS[(tag >>> 6) & 0x3];
  const constructed = (tag & 0x20) !== 0;
  const tagNumber = tag & 0x1f;

  const lenRes = readLength(buf, offset + 1);
  const contentStart = offset + 1 + lenRes.consumed;
  if (contentStart + lenRes.length > buf.length) {
    throw new InvalidAssetError('declared length exceeds available bytes');
  }
  const content = buf.subarray(contentStart, contentStart + lenRes.length);

  const ast = {
    tag,
    tagClass,
    constructed,
    tagNumber,
    length: lenRes.length,
    content: Buffer.from(content),
  };

  if (constructed) {
    ast.children = [];
    let pos = 0;
    while (pos < content.length) {
      const child = walkTlvs(content, pos, depth + 1);
      ast.children.push(child.ast);
      pos = child.endOffset;
    }
  }

  return { ast, endOffset: contentStart + lenRes.length };
}

function parseDer(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf.length === 0) {
    throw new InvalidAssetError('empty input');
  }
  const result = walkTlvs(buf, 0, 0);
  if (result.endOffset !== buf.length) {
    throw new InvalidAssetError('trailing bytes after DER TLV');
  }
  return result.ast;
}

module.exports = { parseDer, InvalidAssetError, DecompressionError };
