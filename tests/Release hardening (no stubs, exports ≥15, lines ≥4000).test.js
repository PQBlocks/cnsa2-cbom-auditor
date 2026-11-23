'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.dirname(__dirname);
const SRC_INDEX = path.join(ROOT, 'src', 'index.js');

test('S-20: src/index.js exports >= 15 public interfaces', () => {
  const mod = require(SRC_INDEX);
  const exportKeys = Object.keys(mod);
  assert.ok(
    exportKeys.length >= 15,
    `Expected >= 15 public exports, got ${exportKeys.length}: ${exportKeys.join(', ')}`
  );

  // Validate core functions exist and are callable
  assert.equal(typeof mod.scan, 'function');
  assert.equal(typeof mod.scanToCbom, 'function');
  assert.equal(typeof mod.generateCbom, 'function');
  assert.equal(typeof mod.verifyCbom, 'function');
  assert.equal(typeof mod.classify, 'function');
  assert.equal(typeof mod.compareCboms, 'function');
});

test('S-20: no stub or placeholder errors in src/ implementation', () => {
  const srcDir = path.join(ROOT, 'src');
  const files = fs.readdirSync(srcDir).filter((f) => f.endsWith('.js'));
  const stubRegex = /throw\s+new\s+\w*Error\(\s*['"`][^'"`]*(?:not (?:yet )?implemented|todo|stub)/i;

  for (const file of files) {
    const content = fs.readFileSync(path.join(srcDir, file), 'utf8');
    assert.ok(!stubRegex.test(content), `Found stub error in src/${file}`);
  }
});
