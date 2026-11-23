'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const LANE = path.dirname(__dirname);
const BIN_VERIFY = path.join(LANE, 'bin', 'verify.js');
const BIN_CLI = path.join(LANE, 'bin', 'pqblocks-cnsa-evidence');
const SAMPLE = path.join(LANE, 'golden-vectors', 'expected', 'sample-cbom.json');

function runBin(bin, args) {
  const result = spawnSync('node', [bin, ...args], { encoding: 'utf8', cwd: LANE });
  return {
    code: result.status ?? 0,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

test('verify: sample-cbom.json passes (bin/verify.js)', () => {
  const result = runBin(BIN_VERIFY, ['--cbom', SAMPLE]);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes('valid') || result.stdout.includes('pass'), result.stdout);
});

test('verify: sample-cbom.json passes with leading verify subcommand', () => {
  const result = runBin(BIN_VERIFY, ['verify', '--cbom', SAMPLE]);
  assert.equal(result.code, 0, result.stderr);
});

test('verify: mutated CBOM fails (bin/verify.js)', () => {
  const bom = JSON.parse(fs.readFileSync(SAMPLE, 'utf8'));
  bom.specVersion = '1.5';
  const tmp = path.join('/tmp/scratchpad', 'mutated-s16.json');
  fs.mkdirSync('/tmp/scratchpad', { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(bom));
  const result = runBin(BIN_VERIFY, ['--cbom', tmp]);
  assert.notEqual(result.code, 0);
});

test('verify: mutated CBOM (extra property) fails', () => {
  const bom = JSON.parse(fs.readFileSync(SAMPLE, 'utf8'));
  bom.extraField = 'nope';
  const tmp = path.join('/tmp/scratchpad', 'mutated-extra-s16.json');
  fs.mkdirSync('/tmp/scratchpad', { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(bom));
  const result = runBin(BIN_VERIFY, ['--cbom', tmp]);
  assert.notEqual(result.code, 0);
});

test('verify: missing --cbom exits with usage code 4', () => {
  const result = runBin(BIN_VERIFY, []);
  assert.equal(result.code, 4);
});

test('verify: non-existent CBOM exits non-zero', () => {
  const result = runBin(BIN_VERIFY, ['--cbom', '/non/existent.json']);
  assert.notEqual(result.code, 0);
});

test('verify: --fail-on option accepted', () => {
  const result = runBin(BIN_VERIFY, ['--cbom', SAMPLE, '--fail-on', 'disallowed']);
  assert.ok([0, 3].includes(result.code));
});

test('CLI: verify subcommand works via main CLI', () => {
  const result = runBin(BIN_CLI, ['verify', '--cbom', SAMPLE]);
  assert.equal(result.code, 0, result.stderr);
});

test('lib/verify.js exports verifyCbom', () => {
  const v = require('../lib/verify.js');
  assert.equal(typeof v.verifyCbom, 'function');
  const r = v.verifyCbom(SAMPLE);
  assert.equal(r.valid, true);
});
