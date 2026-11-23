// lib/deterministic.js — S-14: Deterministic output (sorted, stable serial).
//
// finalizeCbom(bom) -> Bom
// sortComponents(components) -> Component[]
// stableStringify(value, indent?) -> string
// canonicalize(value) -> any
// contentHashHex(bom) -> string
// serialNumberFromContent(bom) -> string
//
// PURPOSE
//   Make a CycloneDX 1.6 CBOM byte-for-byte reproducible (brief/research-brief.md
//   §6.3 "Enterprise: deterministic output (sorted components by `bom-ref`,
//   stable serial derived from content hash) so a CBOM diff between two builds
//   is meaningful", spec/spec.md S-14):
//
//     1. components sorted ascending by `bom-ref`;
//     2. `serialNumber` = `urn:uuid:<sha256(content)>` — a content-derived
//        serial that is stable across rebuilds of identical content.
//
// CONTENT DEFINITION
//   The "content" that is hashed is the canonical JSON of the BOM object with
//   two exclusions:
//
//     - `serialNumber` — circular by construction;
//     - `metadata.timestamp` — volatile build metadata. Including it would give
//       every rebuild a new serial and defeat the stated purpose (a meaningful
//       diff between two builds). Callers pin `metadata.timestamp` themselves
//       (e.g. SOURCE_DATE_EPOCH) when they want bit-identical documents.
//
//   Everything else — bomFormat, specVersion, version, metadata.tools, all
//   properties, and the (sorted) components — is content. Canonical form:
//   object keys sorted lexicographically at every depth, arrays kept in their
//   (sorted, for components) order, serialized with no insignificant whitespace
//   for hashing and with sorted keys for output.
//
// SERIAL LAYOUT
//   The CycloneDX 1.6 schema requires serialNumber to match
//   `^urn:uuid:[0-9a-f]{8}-...-[0-9a-f]{12}$` (brief/references/
//   cyclonedx-bom-1.6.schema.json, RFC 4122). A raw 64-hex sha256 does not
//   match, so the first 16 bytes of the content sha256 are rendered in RFC
//   4122 8-4-4-4-12 hex layout: `urn:uuid:` + that grouping. This is a
//   content hash, not a random UUID and not a UUIDv5 (that is SHA-1-based);
//   the derivation is documented here and reproduced in the S-14 tests.
//
// INPUT / OUTPUT CONTRACT
//   - CDx boms are JSON values (plain objects, arrays, strings, numbers,
//     booleans, null). Class instances, Dates, Buffers and functions are out
//     of contract; canonicalize() keeps serializable values as-is.
//   - finalizeCbom NEVER mutates its input; it returns a new BOM.
//   - Loud failure, never silent repair: non-array components, a missing,
//     empty or non-string `bom-ref`, and duplicate `bom-ref`s each throw
//     InvalidBomError with the offending index/ref in the message.
//   - Validation against the CycloneDX 1.6 schema is NOT performed here; that
//     is S-07 (generateCbom) / S-16 (verify). This module is the emission-format
//     step those layers can call.
//
// WIRING
//   S-14 ships this module standalone; the scan/CLI emission path is wired to
//   it by a later integration slice (S-18 e2e / S-16/S-17 subcommands). The
//   existing S-07 behaviour (caller-supplied serialNumber honoured, sample
//   component order) is intentionally unchanged.

'use strict';

const crypto = require('crypto');

class InvalidBomError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidBomError';
  }
}

// Deep-clone a JSON value with object keys sorted lexicographically at every
// depth. Arrays keep their order. Input is not mutated.
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonicalize(value[key]);
    return out;
  }
  return value;
}

// JSON bytes of the canonical form; indent 0 => compact (used for hashing).
function stableStringify(value, indent = 2) {
  return JSON.stringify(canonicalize(value), null, indent);
}

function describeRef(ref) {
  const t = typeof ref;
  if (t !== 'string') return t + ' ' + JSON.stringify(ref);
  return JSON.stringify(ref);
}

// Stable-validate + sort components ascending by `bom-ref` (UTF-16 code unit
// order). Returns a new array. Throws InvalidBomError otherwise.
function sortComponents(components) {
  if (!Array.isArray(components)) {
    throw new InvalidBomError(
      'sortComponents expects an array of components, got ' +
      (typeof components) + ' ' + JSON.stringify(components) +
      ' — pass bom.components (an array)');
  }
  const seen = new Map();
  for (let i = 0; i < components.length; i++) {
    const comp = components[i];
    const ref = comp && typeof comp === 'object' ? comp['bom-ref'] : undefined;
    if (typeof ref !== 'string' || ref.length === 0) {
      throw new InvalidBomError(
        'component at index ' + i + ' has no valid bom-ref (expected a non-empty string, got ' +
        describeRef(ref) + ')');
    }
    if (seen.has(ref)) {
      throw new InvalidBomError(
        'duplicate bom-ref ' + JSON.stringify(ref) + ' at index ' + i +
        ' (first seen at index ' + seen.get(ref) + ') — bom-refs must be unique so a CBOM diff is unambiguous');
    }
    seen.set(ref, i);
  }
  return [...components].sort((a, b) => {
    const x = a['bom-ref'];
    const y = b['bom-ref'];
    if (x < y) return -1;
    if (x > y) return 1;
    return 0; // unreachable: duplicates are rejected above
  });
}

// The content view that feeds the hash: canonical clone minus serialNumber
// (circular) and minus metadata.timestamp (volatile). Components are sorted.
function contentView(bom) {
  if (!bom || typeof bom !== 'object' || Array.isArray(bom)) {
    throw new TypeError(
      'contentHashHex expects a BOM object, got ' +
      (Array.isArray(bom) ? 'array' : typeof bom));
  }
  if (!Array.isArray(bom.components)) {
    throw new InvalidBomError(
      'bom.components must be an array of components, got ' + describeRef(bom.components));
  }
  const view = canonicalize(bom);
  delete view.serialNumber;
  if (view.metadata && typeof view.metadata === 'object') {
    delete view.metadata.timestamp;
  }
  view.components = sortComponents(view.components);
  return view;
}

function contentHashHex(bom) {
  const canonical = JSON.stringify(contentView(bom));
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function serialNumberFromContent(bom) {
  const view = contentView(bom);
  const canonical = JSON.stringify(view);
  const digest = crypto.createHash('sha256').update(canonical, 'utf8').digest();
  const hex = digest.subarray(0, 16).toString('hex'); // first 16 bytes = 32 hex chars
  const grouped = [
    hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
    hex.slice(16, 20), hex.slice(20, 32),
  ].join('-');
  return 'urn:uuid:' + grouped;
}

// finalizeCbom(bom) -> Bom (new object)
// Sorts components by bom-ref and sets a content-derived serialNumber.
// Never mutates the input.
function finalizeCbom(bom) {
  if (!bom || typeof bom !== 'object' || Array.isArray(bom)) {
    throw new TypeError(
      'finalizeCbom expects a BOM object, got ' +
      (Array.isArray(bom) ? 'array' : typeof bom));
  }
  if (!Array.isArray(bom.components)) {
    throw new InvalidBomError(
      'bom.components must be an array of components, got ' + describeRef(bom.components));
  }
  const components = sortComponents(bom.components); // throws on invalid refs/duplicates
  const withContent = { ...bom, components };
  const serialNumber = serialNumberFromContent(withContent);
  return canonicalize({ ...withContent, serialNumber });
}

module.exports = {
  canonicalize,
  stableStringify,
  sortComponents,
  contentHashHex,
  serialNumberFromContent,
  finalizeCbom,
  InvalidBomError,
};
