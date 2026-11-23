'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseDer, InvalidAssetError, DecompressionError } = require('../lib/der.js');

// --- helpers ----------------------------------------------------------------

function derLength(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  let v = len;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), Buffer.from(bytes)]);
}

function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), Buffer.from(content)]);
}

function seqOf(children) {
  const content = Buffer.concat(children);
  return Buffer.concat([Buffer.from([0x30]), derLength(content.length), content]);
}

// --- exports ----------------------------------------------------------------

test('exports parseDer, InvalidAssetError, DecompressionError', () => {
  assert.equal(typeof parseDer, 'function');
  assert.equal(InvalidAssetError.prototype instanceof Error, true);
  assert.equal(DecompressionError.prototype instanceof Error, true);
});

// --- happy path -------------------------------------------------------------

test('parses a simple primitive TLV (INTEGER)', () => {
  const bytes = Buffer.from([0x02, 0x01, 0x05]);
  const ast = parseDer(bytes);

  assert.equal(ast.tag, 0x02);
  assert.equal(ast.tagClass, 'universal');
  assert.equal(ast.constructed, false);
  assert.equal(ast.tagNumber, 2);
  assert.equal(ast.length, 1);
  assert.deepEqual(ast.content, Buffer.from([0x05]));
  assert.equal(ast.children, undefined);
});

test('parses a constructed SEQUENCE with children', () => {
  const inner = Buffer.from([0x02, 0x01, 0x05]);
  const bytes = seqOf([inner]);
  const ast = parseDer(bytes);

  assert.equal(ast.tag, 0x30);
  assert.equal(ast.tagClass, 'universal');
  assert.equal(ast.constructed, true);
  assert.equal(ast.tagNumber, 16);
  assert.equal(ast.length, 3);
  assert.equal(ast.children.length, 1);
  assert.equal(ast.children[0].tagNumber, 2);
  assert.deepEqual(ast.children[0].content, Buffer.from([0x05]));
});

test('parses long-form length correctly (200-byte content)', () => {
  const content = Buffer.alloc(200, 0x41);
  const bytes = Buffer.concat([Buffer.from([0x02, 0x81, 0xC8]), content]);
  const ast = parseDer(bytes);

  assert.equal(ast.length, 200);
  assert.equal(ast.content.length, 200);
  assert.deepEqual(ast.content, content);
});

test('parses empty constructed SEQUENCE', () => {
  const bytes = Buffer.from([0x30, 0x00]);
  const ast = parseDer(bytes);

  assert.equal(ast.length, 0);
  assert.equal(ast.content.length, 0);
  assert.deepEqual(ast.children, []);
});

test('parses context-specific tag (e.g. [0] EXPLICIT)', () => {
  const inner = Buffer.from([0x02, 0x01, 0x05]);
  const bytes = seqOf([tlv(0xa0, inner)]);
  const ast = parseDer(bytes);

  assert.equal(ast.children[0].tagClass, 'context-specific');
  assert.equal(ast.children[0].tagNumber, 0);
  assert.equal(ast.children[0].constructed, true);
});

// --- negative: indefinite length -------------------------------------------

test('rejects indefinite-length encoding (BER 0x80 length)', () => {
  const bytes = Buffer.from([0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]);
  assert.throws(() => parseDer(bytes), DecompressionError);
});

test('rejects indefinite-length inside a constructed child', () => {
  const inner = Buffer.from([0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00]);
  const bytes = seqOf([inner]);
  assert.throws(() => parseDer(bytes), DecompressionError);
});

// --- negative: depth bound --------------------------------------------------

function encodeLength(len) {
  if (len < 128) {
    return Buffer.from([len]);
  }
  const bytes = [];
  let remaining = len;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function makeSequence(content) {
  return Buffer.concat([Buffer.from([0x30]), encodeLength(content.length), content]);
}

test('rejects nesting depth greater than 128', () => {
  let inner = Buffer.from([0x02, 0x01, 0x05]);
  for (let i = 0; i < 129; i++) {
    inner = makeSequence(inner);
  }
  assert.throws(() => parseDer(inner), InvalidAssetError);
});

test('accepts nesting depth exactly 128', () => {
  let inner = Buffer.from([0x02, 0x01, 0x05]);
  for (let i = 0; i < 128; i++) {
    inner = makeSequence(inner);
  }
  const ast = parseDer(inner);
  assert.ok(ast);
  assert.equal(ast.constructed, true);
});

// --- negative: length cap ---------------------------------------------------

test('rejects declared length greater than 10 MB', () => {
  // 10 MB = 10485760 = 0xA00000; use 10485761 = 0xA00001 (3 long-form length bytes)
  const lengthBytes = Buffer.from([0xA0, 0x00, 0x01]);
  const bytes = Buffer.concat([Buffer.from([0x30, 0x83]), lengthBytes]);
  assert.throws(() => parseDer(bytes), InvalidAssetError);
});

test('accepts declared length exactly 10 MB', () => {
  const lengthBytes = Buffer.from([0xA0, 0x00, 0x00]); // exactly 10485760
  const bytes = Buffer.concat([Buffer.from([0x30, 0x83]), lengthBytes]);
  assert.throws(() => parseDer(bytes), InvalidAssetError);
});

// --- negative: truncation ---------------------------------------------------

test('rejects truncated content (declared length exceeds available bytes)', () => {
  const bytes = Buffer.from([0x02, 0x05, 0x01, 0x02]);
  assert.throws(() => parseDer(bytes), InvalidAssetError);
});

test('rejects empty input', () => {
  assert.throws(() => parseDer(Buffer.alloc(0)), InvalidAssetError);
});

test('rejects tag byte with no length byte', () => {
  assert.throws(() => parseDer(Buffer.from([0x02])), InvalidAssetError);
});

test('rejects truncated long-form length declaration', () => {
  // 0x82 says 2 length bytes follow, but only 1 is present
  const bytes = Buffer.from([0x02, 0x82, 0x00]);
  assert.throws(() => parseDer(bytes), InvalidAssetError);
});

// --- error classes ----------------------------------------------------------

test('InvalidAssetError is an Error with correct name', () => {
  const err = new InvalidAssetError('boom');
  assert.equal(err.name, 'InvalidAssetError');
  assert.ok(err instanceof Error);
  assert.equal(err.message, 'boom');
});

test('DecompressionError is an Error with correct name', () => {
  const err = new DecompressionError('boom');
  assert.equal(err.name, 'DecompressionError');
  assert.ok(err instanceof Error);
  assert.equal(err.message, 'boom');
});
