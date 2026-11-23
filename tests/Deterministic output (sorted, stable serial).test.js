'use strict';
// S-14 — Deterministic output (sorted, stable serial)
// Acceptance (spec/spec.md S-14): `lib/deterministic.js` — components sorted by
// `bom-ref`; `serialNumber` = `urn:uuid:<sha256(content)>`. Test: two runs on
// same input → bit-identical JSON.
//
// Content definition (deterministic.js module header documents the same):
// canonical JSON of the BOM object with `serialNumber` removed (circular) and
// `metadata.timestamp` removed (volatile build time; the serial must be stable
// across rebuilds so a CBOM diff between two builds is meaningful —
// brief/research-brief.md §6.3 "Enterprise: deterministic output ... stable
// serial derived from content hash so a CBOM diff between two builds is
// meaningful"). Everything else in the document is content.
//
// Non-circularity: expected values in these tests are computed from the brief's
// definition (sha256 over canonical content) or asserted as invariants
// (stability, order-independence, schema-pattern match). Nothing is asserted by
// re-deriving it with the implementation's own helpers except where indicated.
// The finalized CBOM is validated against the real CycloneDX 1.6 schema
// (brief/references/cyclonedx-bom-1.6.schema.json) with the two external refs
// (spdx.schema.json, jsf-0.82.schema.json) stubbed — same approach as the S-07
// test — which proves the content-derived serialNumber passes the schema's
// RFC 4122 urn:uuid pattern.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const LANE = path.dirname(__dirname);

const CDX_SERIAL_PATTERN = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function sampleBom() {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
    version: 1,
    metadata: {
      timestamp: '2026-11-15T00:00:00.000Z',
      tools: {
        components: [
          { type: 'application', name: 'pqblocks-cnsa-evidence', version: '0.1.0' },
        ],
      },
      properties: [
        { name: 'classification:oracle', value: 'test-oracle' },
      ],
    },
    components: [
      { type: 'cryptographic-asset', 'bom-ref': 'crypto-asset:bbbbbbbbbbbbbbbb', name: 'b.crt' },
      { type: 'cryptographic-asset', 'bom-ref': 'crypto-asset:aaaaaaaaaaaaaaaa', name: 'a.crt' },
      { type: 'cryptographic-asset', 'bom-ref': 'crypto-asset:cccccccccccccccc', name: 'c.crt' },
    ],
  };
}

function loadSchemaValidator() {
  const Ajv = require('ajv').default || require('ajv');
  const schema = JSON.parse(fs.readFileSync(
    (fs.existsSync(path.join(LANE, 'src', 'schema', 'cyclonedx-bom-1.6.schema.json')) ? path.join(LANE, 'src', 'schema', 'cyclonedx-bom-1.6.schema.json') : path.join(LANE, 'brief', 'references', 'cyclonedx-bom-1.6.schema.json')), 'utf8'));
  delete schema.$schema;
  const ajv = new Ajv({
    allErrors: true, strict: false, strictSchema: false,
    validateSchema: false, allowUnionTypes: true,
  });
  const base = 'http://cyclonedx.org/schema/';
  ajv.addSchema({
    $id: base + 'spdx.schema.json',
    type: ['object', 'string', 'number', 'integer', 'boolean', 'array', 'null'],
  });
  ajv.addSchema({
    $id: base + 'jsf-0.82.schema.json',
    definitions: { signature: { type: ['object', 'null'] } },
  });
  return ajv.compile(schema);
}

function pemToDer(relPath) {
  const pem = fs.readFileSync(path.join(LANE, 'golden-vectors', relPath), 'utf8');
  return Buffer.from(
    pem.split(/\r?\n/).filter((l) => l && !l.startsWith('-----')).join(''),
    'base64',
  );
}

test('exports the S-14 API surface', () => {
  const m = require('../lib/deterministic.js');
  for (const name of [
    'canonicalize', 'stableStringify', 'sortComponents',
    'contentHashHex', 'serialNumberFromContent', 'finalizeCbom',
    'InvalidBomError',
  ]) {
    assert.equal(typeof m[name], name === 'InvalidBomError' ? 'function' : 'function',
      'missing export ' + name);
  }
  assert.ok(m.InvalidBomError.prototype instanceof Error);
});

test('canonicalize sorts object keys recursively and preserves array order', () => {
  const { canonicalize } = require('../lib/deterministic.js');
  const input = { b: 1, a: { d: 4, c: { z: 26, y: 25 } }, list: [{ b: 2, a: 1 }, 3] };
  const out = canonicalize(input);
  assert.deepEqual(Object.keys(out), ['a', 'b', 'list']);
  assert.deepEqual(Object.keys(out.a), ['c', 'd']);
  assert.deepEqual(Object.keys(out.a.c), ['y', 'z']);
  assert.deepEqual(out.list.map((x) => (typeof x === 'object' ? Object.keys(x) : x)),
    [['a', 'b'], 3]);
});

test('canonicalize does not mutate its input', () => {
  const { canonicalize } = require('../lib/deterministic.js');
  const input = { b: 1, a: { d: 4, c: 3 } };
  const snapshot = JSON.stringify(input);
  canonicalize(input);
  assert.equal(JSON.stringify(input), snapshot);
});

test('stableStringify produces identical bytes for key-permuted deep clones', () => {
  const { stableStringify } = require('../lib/deterministic.js');
  const a = { x: 1, nested: { p: 1, q: [3, 2, 1], r: { m: 2, n: 1 } }, y: 's' };
  const b = { y: 's', nested: { r: { n: 1, m: 2 }, q: [3, 2, 1], p: 1 }, x: 1 };
  assert.equal(stableStringify(a), stableStringify(b));
});

test('stableStringify defaults to 2-space indent and honours the indent argument', () => {
  const { stableStringify } = require('../lib/deterministic.js');
  assert.equal(stableStringify({ b: 1, a: 2 }), JSON.stringify({ a: 2, b: 1 }, null, 2));
  assert.equal(stableStringify({ b: 1, a: 2 }, 0), '{"a":2,"b":1}');
});

test('sortComponents returns a new array sorted ascending by bom-ref', () => {
  const { sortComponents } = require('../lib/deterministic.js');
  const comps = sampleBom().components;
  const out = sortComponents(comps);
  assert.notEqual(out, comps);
  assert.deepEqual(out.map((c) => c['bom-ref']), [
    'crypto-asset:aaaaaaaaaaaaaaaa',
    'crypto-asset:bbbbbbbbbbbbbbbb',
    'crypto-asset:cccccccccccccccc',
  ]);
  // input positional order untouched
  assert.equal(comps[0]['bom-ref'], 'crypto-asset:bbbbbbbbbbbbbbbb');
});

test('sortComponents rejects non-array input with an actionable error', () => {
  const { sortComponents, InvalidBomError } = require('../lib/deterministic.js');
  assert.throws(() => sortComponents('not-an-array'), (err) => {
    assert.ok(err instanceof InvalidBomError);
    assert.match(err.message, /array/i);
    return true;
  });
});

test('sortComponents rejects a component without a bom-ref, naming its index', () => {
  const { sortComponents, InvalidBomError } = require('../lib/deterministic.js');
  const comps = [
    { type: 'cryptographic-asset', 'bom-ref': 'crypto-asset:aaaaaaaaaaaaaaaa' },
    { type: 'cryptographic-asset', name: 'no-ref.crt' },
  ];
  assert.throws(() => sortComponents(comps), (err) => {
    assert.ok(err instanceof InvalidBomError);
    assert.match(err.message, /index 1/);
    return true;
  });
});

test('sortComponents rejects a non-string bom-ref', () => {
  const { sortComponents, InvalidBomError } = require('../lib/deterministic.js');
  assert.throws(
    () => sortComponents([{ 'bom-ref': 42 }]),
    (err) => err instanceof InvalidBomError && /bom-ref/.test(err.message),
  );
});

test('sortComponents rejects duplicate bom-refs (diff integrity)', () => {
  const { sortComponents, InvalidBomError } = require('../lib/deterministic.js');
  const dup = [
    { 'bom-ref': 'crypto-asset:aaaaaaaaaaaaaaaa', name: 'one.crt' },
    { 'bom-ref': 'crypto-asset:aaaaaaaaaaaaaaaa', name: 'two.crt' },
  ];
  assert.throws(() => sortComponents(dup), (err) => {
    assert.ok(err instanceof InvalidBomError);
    assert.match(err.message, /duplicate/i);
    return true;
  });
});

test('contentHashHex returns a 64-char lowercase hex sha256', () => {
  const { contentHashHex } = require('../lib/deterministic.js');
  assert.match(contentHashHex(sampleBom()), /^[0-9a-f]{64}$/);
});

test('contentHashHex ignores the serialNumber value', () => {
  const { contentHashHex } = require('../lib/deterministic.js');
  const a = sampleBom();
  const b = { ...sampleBom(), serialNumber: 'urn:uuid:ffffffff-ffff-ffff-ffff-ffffffffffff' };
  assert.equal(contentHashHex(a), contentHashHex(b));
});

test('contentHashHex ignores metadata.timestamp (volatile build time)', () => {
  const { contentHashHex } = require('../lib/deterministic.js');
  const a = sampleBom();
  const b = sampleBom();
  b.metadata = { ...b.metadata, timestamp: '2030-01-01T00:00:00.000Z' };
  assert.equal(contentHashHex(a), contentHashHex(b));
});

test('contentHashHex is independent of key insertion order', () => {
  const { contentHashHex } = require('../lib/deterministic.js');
  const a = sampleBom();
  const reordered = {
    components: sampleBom().components,
    metadata: sampleBom().metadata,
    version: 1,
    serialNumber: sampleBom().serialNumber,
    specVersion: '1.6',
    bomFormat: 'CycloneDX',
  };
  assert.equal(contentHashHex(a), contentHashHex(reordered));
});

test('contentHashHex is independent of component order (components are sorted content)', () => {
  const { contentHashHex } = require('../lib/deterministic.js');
  const a = sampleBom();
  const b = sampleBom();
  b.components = [...b.components].reverse();
  assert.equal(contentHashHex(a), contentHashHex(b));
});

test('contentHashHex changes when any content byte changes', () => {
  const { contentHashHex } = require('../lib/deterministic.js');
  const a = sampleBom();
  const b = sampleBom();
  b.components = b.components.map((c) => (c.name === 'a.crt' ? { ...c, name: 'A.crt' } : c));
  assert.notEqual(contentHashHex(a), contentHashHex(b));
});

test('serialNumberFromContent matches the CycloneDX 1.6 serialNumber pattern', () => {
  const { serialNumberFromContent } = require('../lib/deterministic.js');
  assert.match(serialNumberFromContent(sampleBom()), CDX_SERIAL_PATTERN);
});

test('serialNumberFromContent is deterministic across calls', () => {
  const { serialNumberFromContent } = require('../lib/deterministic.js');
  assert.equal(serialNumberFromContent(sampleBom()), serialNumberFromContent(sampleBom()));
});

test('serialNumberFromContent renders the first 16 bytes of the content sha256 as a UUID', () => {
  const { serialNumberFromContent } = require('../lib/deterministic.js');
  const bom = sampleBom();
  // Recompute the expected layout independently of the implementation's internals:
  // sha256 over the canonical compact form of the BOM without serialNumber and
  // without metadata.timestamp, components sorted by bom-ref.
  const view = {
    bomFormat: bom.bomFormat,
    specVersion: bom.specVersion,
    version: bom.version,
    metadata: { ...bom.metadata },
    components: [...bom.components].sort((a, b) => (a['bom-ref'] < b['bom-ref'] ? -1 : 1)),
  };
  delete view.metadata.timestamp;
  const canonical = JSON.stringify(sortKeysDeep(view));
  const hex = crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
  const grouped = [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20, 32)].join('-');
  assert.equal(serialNumberFromContent(bom), 'urn:uuid:' + grouped);
});

function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortKeysDeep(value[key]);
    return out;
  }
  return value;
}

test('finalizeCbom returns a new BOM and does not mutate its input', () => {
  const { finalizeCbom } = require('../lib/deterministic.js');
  const bom = sampleBom();
  const snapshot = JSON.stringify(bom);
  const out = finalizeCbom(bom);
  assert.notEqual(out, bom);
  assert.equal(JSON.stringify(bom), snapshot);
});

test('finalizeCbom sorts components by bom-ref', () => {
  const { finalizeCbom } = require('../lib/deterministic.js');
  const out = finalizeCbom(sampleBom());
  assert.deepEqual(out.components.map((c) => c['bom-ref']), [...out.components.map((c) => c['bom-ref'])].sort());
  assert.equal(out.components[0].name, 'a.crt');
  assert.equal(out.components[2].name, 'c.crt');
});

test('finalizeCbom sets a content-derived serialNumber', () => {
  const { finalizeCbom, serialNumberFromContent } = require('../lib/deterministic.js');
  const bom = sampleBom();
  const out = finalizeCbom(bom);
  assert.equal(out.serialNumber, serialNumberFromContent(bom));
  assert.match(out.serialNumber, CDX_SERIAL_PATTERN);
  assert.notEqual(out.serialNumber, bom.serialNumber);
});

test('finalizeCbom rejects non-object input with a TypeError', () => {
  const { finalizeCbom } = require('../lib/deterministic.js');
  assert.throws(() => finalizeCbom(null), TypeError);
  assert.throws(() => finalizeCbom([1, 2, 3]), TypeError);
  assert.throws(() => finalizeCbom('bom'), TypeError);
});

test('finalizeCbom rejects a BOM whose components are not an array', () => {
  const { finalizeCbom, InvalidBomError } = require('../lib/deterministic.js');
  const bom = { ...sampleBom(), components: 'nope' };
  assert.throws(() => finalizeCbom(bom), (err) => err instanceof InvalidBomError && /components/.test(err.message));
});

test('finalizeCbom rejects duplicate bom-refs', () => {
  const { finalizeCbom, InvalidBomError } = require('../lib/deterministic.js');
  const bom = sampleBom();
  bom.components = [
    { 'bom-ref': 'crypto-asset:aaaaaaaaaaaaaaaa', name: 'x.crt' },
    { 'bom-ref': 'crypto-asset:aaaaaaaaaaaaaaaa', name: 'y.crt' },
  ];
  assert.throws(() => finalizeCbom(bom), (err) => err instanceof InvalidBomError && /duplicate/i.test(err.message));
});

test('two runs on the same input produce bit-identical JSON', () => {
  const { finalizeCbom } = require('../lib/deterministic.js');
  const first = JSON.stringify(finalizeCbom(sampleBom()));
  const second = JSON.stringify(finalizeCbom(structuredClone(sampleBom())));
  assert.equal(first, second);
});

test('shuffled component order produces bit-identical finalized JSON', () => {
  const { finalizeCbom } = require('../lib/deterministic.js');
  const a = sampleBom();
  const b = sampleBom();
  b.components = [b.components[2], b.components[0], b.components[1]];
  assert.equal(JSON.stringify(finalizeCbom(a)), JSON.stringify(finalizeCbom(b)));
});

test('finalized CBOM (real builder output) passes CycloneDX 1.6 schema validation', async () => {
  const { finalizeCbom } = require('../lib/deterministic.js');
  const { generateCbom } = require('../lib/cbom.js');
  const { parseCert } = require('../lib/x509.js');
  const assets = [];
  for (const name of ['ec-p256-sha256.crt', 'mldsa65.crt', 'rsa2048-sha256.crt']) {
    const asset = parseCert(pemToDer('certs/' + name));
    asset.name = name;
    asset.file = 'certs/' + name;
    assets.push(asset);
  }
  const bom = await generateCbom(assets, {
    timestamp: '2026-11-15T00:00:00.000Z',
    oracle: 'test-oracle',
    serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
  });
  const finalized = finalizeCbom(bom);
  const validate = loadSchemaValidator();
  const valid = validate(finalized);
  assert.equal(valid, true, 'finalized CBOM failed CycloneDX 1.6 schema: ' + JSON.stringify(validate.errors, null, 2));
  assert.match(finalized.serialNumber, CDX_SERIAL_PATTERN);
});

test('finalized CBOM rejects a hand-corrupted serialNumber at the schema layer', async () => {
  const { finalizeCbom } = require('../lib/deterministic.js');
  const { generateCbom } = require('../lib/cbom.js');
  const { parseCert } = require('../lib/x509.js');
  const asset = parseCert(pemToDer('certs/ec-p256-sha256.crt'));
  asset.name = 'ec-p256-sha256.crt';
  asset.file = 'certs/ec-p256-sha256.crt';
  const bom = await generateCbom([asset], {
    timestamp: '2026-11-15T00:00:00.000Z',
    oracle: 'test-oracle',
    serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
  });
  const finalized = finalizeCbom(bom);
  const corrupted = { ...finalized, serialNumber: 'urn:uuid:not-a-uuid' };
  const validate = loadSchemaValidator();
  assert.equal(validate(corrupted), false, 'schema must reject a non-RFC-4122 serialNumber');
});
