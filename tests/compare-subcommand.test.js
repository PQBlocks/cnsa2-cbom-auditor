'use strict';

// S-17 — Compare subcommand (before/after diff).
// Contract path contains a slash, so this file is nested: tests/Compare subcommand (before/
// after diff).test.js. LANE is therefore two levels up from __dirname.

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const LANE = path.dirname(__dirname);
const BIN_CLI = path.join(LANE, 'bin', 'pqblocks-cnsa-evidence');
const BIN_COMPARE = path.join(LANE, 'bin', 'compare.js');
const SAMPLE = path.join(LANE, 'golden-vectors', 'expected', 'sample-cbom.json');
const AFTER_DIR = path.join(LANE, 'golden-vectors', 'after');

function runBin(bin, args) {
  const result = spawnSync('node', [bin, ...args], { encoding: 'utf8', cwd: LANE });
  return {
    code: result.status ?? 0,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function setupFixtures() {
  if (!fs.existsSync(AFTER_DIR)) fs.mkdirSync(AFTER_DIR, { recursive: true });
  const bom = JSON.parse(fs.readFileSync(SAMPLE, 'utf8'));

  // after-removed: drop first component
  const removed = JSON.parse(JSON.stringify(bom));
  if (removed.components && removed.components.length > 0) {
    removed.components = removed.components.slice(1);
  }
  fs.writeFileSync(path.join(AFTER_DIR, 'after-removed.json'), JSON.stringify(removed, null, 2));

  // after-added: identical copy (no delta) — but add a synthetic second copy of last comp with new ref
  const added = JSON.parse(JSON.stringify(bom));
  if (added.components && added.components.length > 0) {
    const extra = JSON.parse(JSON.stringify(added.components[added.components.length - 1]));
    extra['bom-ref'] = 'crypto-asset:zzzzzzzzzzzzzzzz';
    extra.name = 'synthetic-added.crt';
    added.components.push(extra);
  }
  fs.writeFileSync(path.join(AFTER_DIR, 'after-added.json'), JSON.stringify(added, null, 2));

  // after-changed: mutate a component property
  const changed = JSON.parse(JSON.stringify(bom));
  if (changed.components && changed.components.length > 1) {
    changed.components[1].cryptoProperties.assetType = 'malicious-asset';
  }
  fs.writeFileSync(path.join(AFTER_DIR, 'after-changed.json'), JSON.stringify(changed, null, 2));
}

const AFTER_REMOVED = path.join(AFTER_DIR, 'after-removed.json');
const AFTER_ADDED = path.join(AFTER_DIR, 'after-added.json');
const AFTER_CHANGED = path.join(AFTER_DIR, 'after-changed.json');

test('compare: before/after diff works with removed component', () => {
  setupFixtures();
  const result = runBin(BIN_CLI, ['compare', '--before', SAMPLE, '--after', AFTER_REMOVED]);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes('Removed:'), 'Expected removed count in output');
  assert.ok(/Removed:\s*[1-9]/.test(result.stdout), 'Expected at least one removed');
});

test('compare: added component detected correctly', () => {
  setupFixtures();
  const result = runBin(BIN_CLI, ['compare', '--before', SAMPLE, '--after', AFTER_ADDED]);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes('Added:'), 'Expected added count in output');
  assert.ok(/Added:\s*[1-9]/.test(result.stdout), 'Expected at least one added');
});

test('compare: changed component detected', () => {
  setupFixtures();
  const result = runBin(BIN_CLI, ['compare', '--before', SAMPLE, '--after', AFTER_CHANGED]);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes('Changed:'), 'Expected changed count in output');
  assert.ok(/Changed:\s*[1-9]/.test(result.stdout), 'Expected at least one changed');
});

test('compare: missing --before exits with usage code 4', () => {
  const result = runBin(BIN_CLI, ['compare']);
  assert.equal(result.code, 4);
});

test('compare: missing --after exits with usage code 4', () => {
  const result = runBin(BIN_CLI, ['compare', '--before', SAMPLE]);
  assert.equal(result.code, 4);
});

test('compare: bin/compare.js standalone works', () => {
  setupFixtures();
  const result = runBin(BIN_COMPARE, ['--before', SAMPLE, '--after', AFTER_CHANGED]);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes('Changed:'));
});

test('compare: lib exports compareCboms function', () => {
  const v = require('../lib/compare');
  assert.equal(typeof v.compareCboms, 'function');
  assert.equal(v.compareCboms.length, 2);
});

test('compare: json format output is valid JSON', () => {
  setupFixtures();
  const result = runBin(BIN_CLI, ['compare', '--before', SAMPLE, '--after', AFTER_CHANGED, '--format', 'json']);
  assert.equal(result.code, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.ok(Array.isArray(parsed.added));
  assert.ok(Array.isArray(parsed.removed));
  assert.ok(Array.isArray(parsed.changed));
});

test('compare: identical CBOMs produce empty diff', () => {
  const v = require('../lib/compare');
  const r = v.compareCboms(SAMPLE, SAMPLE);
  assert.equal(r.added.length, 0);
  assert.equal(r.removed.length, 0);
  assert.equal(r.changed.length, 0);
});

test('compare: non-existent file throws/errs non-zero', () => {
  const result = runBin(BIN_CLI, ['compare', '--before', '/no/such/file.json', '--after', SAMPLE]);
  assert.notEqual(result.code, 0);
});

test('compare: lib compareCboms detects added/removed/changed programmatically', () => {
  setupFixtures();
  const v = require('../lib/compare');
  const r1 = v.compareCboms(SAMPLE, AFTER_REMOVED);
  assert.equal(r1.removed.length, 1);
  const r2 = v.compareCboms(SAMPLE, AFTER_ADDED);
  assert.equal(r2.added.length, 1);
  const r3 = v.compareCboms(SAMPLE, AFTER_CHANGED);
  assert.equal(r3.changed.length, 1);
});

test('compare: lib throws on missing components (before)', () => {
  const v = require('../lib/compare');
  assert.throws(() => v.compareCboms({ foo: 1 }, SAMPLE), /missing components/);
});

test('compare: lib throws on missing components (after)', () => {
  const v = require('../lib/compare');
  assert.throws(() => v.compareCboms(SAMPLE, { foo: 1 }), /missing components/);
});

test('compare: lib throws on non-object input', () => {
  const v = require('../lib/compare');
  assert.throws(() => v.compareCboms(42, SAMPLE));
});

test('compare: lib throws on invalid JSON string', () => {
  const v = require('../lib/compare');
  assert.throws(() => v.compareCboms('{not json', SAMPLE), /Invalid JSON/);
});

test('compare: deepEqual exported and works', () => {
  const v = require('../lib/compare');
  assert.equal(v.deepEqual({ a: 1 }, { a: 1 }), true);
  assert.equal(v.deepEqual({ a: 1 }, { a: 2 }), false);
});

test('compare: renderCompareTable exported', () => {
  const v = require('../lib/compare');
  const out = v.renderCompareTable({ added: [], removed: [], changed: [] });
  assert.ok(out.includes('Added: 0'));
});
