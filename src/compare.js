'use strict';
// S-17: Compare subcommand (before/after diff)
// Public API: compareCboms(before, after) -> { added, removed, changed }
// `before`/`after` may be a file path, a JSON string, or a parsed CBOM object.

const fs = require('node:fs');

function readCbom(input) {
  if (Buffer.isBuffer(input)) input = input.toString('utf8');
  if (typeof input === 'string') {
    // If it points at an existing file, read it; otherwise treat as JSON text.
    try {
      if (fs.existsSync(input)) {
        return JSON.parse(fs.readFileSync(input, 'utf8'));
      }
    } catch (_) {
      // fall through to JSON parse
    }
    try {
      return JSON.parse(input);
    } catch (err) {
      const e = new Error('Invalid JSON: ' + err.message);
      e.code = 'INVALID_JSON';
      throw e;
    }
  }
  if (input && typeof input === 'object' && !Array.isArray(input)) {
    return input;
  }
  const e = new TypeError('compareCboms expects a file path, JSON string, or object');
  e.code = 'E_TYPE';
  throw e;
}

function validateBom(bom, label) {
  if (!bom || typeof bom !== 'object' || Array.isArray(bom)) {
    const e = new TypeError(`invalid ${label} CBOM: not an object`);
    e.code = 'E_TYPE';
    throw e;
  }
  if (!Array.isArray(bom.components)) {
    const e = new Error(`invalid ${label} CBOM: missing components array`);
    e.code = 'INVALID_CBOM';
    throw e;
  }
}

function deepEqual(objA, objB) {
  if (objA === objB) return true;
  if (typeof objA !== 'object' || typeof objB !== 'object' || objA === null || objB === null) {
    return objA === objB;
  }
  if (Array.isArray(objA) !== Array.isArray(objB)) return false;

  const keysA = Object.keys(objA);
  const keysB = Object.keys(objB);
  if (keysA.length !== keysB.length) return false;

  for (const key of keysA) {
    if (!Object.prototype.hasOwnProperty.call(objB, key)) return false;
    if (!deepEqual(objA[key], objB[key])) return false;
  }
  return true;
}

function compareCboms(before, after) {
  const beforeBom = readCbom(before);
  const afterBom = readCbom(after);

  validateBom(beforeBom, 'before');
  validateBom(afterBom, 'after');

  const beforeByRef = new Map();
  const afterByRef = new Map();

  for (const comp of beforeBom.components) {
    const ref = comp && comp['bom-ref'];
    if (ref) beforeByRef.set(ref, comp);
  }
  for (const comp of afterBom.components) {
    const ref = comp && comp['bom-ref'];
    if (ref) afterByRef.set(ref, comp);
  }

  const added = [];
  const removed = [];
  const changed = [];

  for (const ref of afterByRef.keys()) {
    if (!beforeByRef.has(ref)) {
      added.push(afterByRef.get(ref));
    }
  }
  for (const ref of beforeByRef.keys()) {
    if (!afterByRef.has(ref)) {
      removed.push(beforeByRef.get(ref));
    } else {
      const beforeComp = beforeByRef.get(ref);
      const afterComp = afterByRef.get(ref);
      if (!deepEqual(beforeComp, afterComp)) {
        changed.push({ bomRef: ref, before: beforeComp, after: afterComp });
      }
    }
  }

  // Deterministic ordering: sort by bom-ref for stable output.
  const byRef = (a, b) => String(a && a['bom-ref']).localeCompare(String(b && b['bom-ref']));
  added.sort(byRef);
  removed.sort(byRef);
  changed.sort((a, b) => String(a.bomRef).localeCompare(String(b.bomRef)));

  return { added, removed, changed };
}

function renderCompareTable(result) {
  const lines = [];
  lines.push(`Added: ${result.added.length}`);
  lines.push(`Removed: ${result.removed.length}`);
  lines.push(`Changed: ${result.changed.length}`);

  if (result.added.length > 0) {
    lines.push('');
    lines.push('Added components:');
    for (const comp of result.added) {
      const name = (comp && comp.name) || 'unknown';
      lines.push(`  + ${name} (${comp['bom-ref']})`);
    }
  }

  if (result.removed.length > 0) {
    lines.push('');
    lines.push('Removed components:');
    for (const comp of result.removed) {
      const name = (comp && comp.name) || 'unknown';
      lines.push(`  - ${name} (${comp['bom-ref']})`);
    }
  }

  if (result.changed.length > 0) {
    lines.push('');
    lines.push('Changed components:');
    for (const change of result.changed) {
      const name = (change.after && change.after.name) || 'unknown';
      lines.push(`  ~ ${name} (${change.bomRef}): changed`);
    }
  }

  return lines.join('\n');
}

module.exports = { compareCboms, compare: compareCboms, deepEqual, renderCompareTable, readCbom };
