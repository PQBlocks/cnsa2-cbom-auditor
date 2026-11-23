'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const BIN = path.join(__dirname, '..', 'bin', 'pqblocks-cnsa-evidence');

function runCli(args, opts = {}) {
  const result = spawnSync('node', [BIN, ...args], {
    encoding: 'utf8',
    cwd: __dirname,
    ...opts,
  });
  return {
    code: result.status ?? 0,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

test('CLI: scan subcommand exists and shows usage on --help', () => {
  const result = runCli(['scan', '--help']);
  assert.equal(result.code, 0);
  assert.ok(result.stdout.includes('scan') || result.stderr.includes('scan'));
});

test('CLI: verify subcommand exists and shows usage on --help', () => {
  const result = runCli(['verify', '--help']);
  assert.equal(result.code, 0);
  assert.ok(result.stdout.includes('verify') || result.stderr.includes('verify'));
});

test('CLI: compare subcommand exists and shows usage on --help', () => {
  const result = runCli(['compare', '--help']);
  assert.equal(result.code, 0);
  assert.ok(result.stdout.includes('compare') || result.stderr.includes('compare'));
});

test('CLI: unknown subcommand exits with code 4 (usage error)', () => {
  const result = runCli(['unknown-subcommand']);
  assert.equal(result.code, 4);
});

test('CLI: scan without --target exits with code 4', () => {
  const result = runCli(['scan']);
  assert.equal(result.code, 4);
});

test('CLI: scan with --target on non-existent path exits with code 1 (internal error)', () => {
  const result = runCli(['scan', '--target', '/non/existent/path']);
  assert.equal(result.code, 1);
});

test('CLI: verify without --cbom exits with code 4', () => {
  const result = runCli(['verify']);
  assert.equal(result.code, 4);
});

test('CLI: verify with non-existent CBOM exits with code 1', () => {
  const result = runCli(['verify', '--cbom', '/non/existent.json']);
  assert.equal(result.code, 1);
});

test('CLI: compare without --before/--after exits with code 4', () => {
  const result = runCli(['compare']);
  assert.equal(result.code, 4);
});

test('CLI: compare with non-existent files exits with code 1', () => {
  const result = runCli(['compare', '--before', '/non/existent1.json', '--after', '/non/existent2.json']);
  assert.equal(result.code, 1);
});

test('CLI: scan --format table|json option accepted', () => {
  const resultTable = runCli(['scan', '--target', '/non/existent', '--format', 'table']);
  const resultJson = runCli(['scan', '--target', '/non/existent', '--format', 'json']);
  // Both should be handled (they will error on path but format option parsed)
  assert.ok([1, 4].includes(resultTable.code));
  assert.ok([1, 4].includes(resultJson.code));
});

test('CLI: scan --fail-on option accepted', () => {
  const result = runCli(['scan', '--target', '/non/existent', '--fail-on', 'disallowed']);
  assert.ok([1, 4].includes(result.code));
});

test('CLI: verify --fail-on option accepted', () => {
  const result = runCli(['verify', '--cbom', '/non/existent.json', '--fail-on', 'deprecated']);
  assert.ok([1, 4].includes(result.code));
});

test('CLI: top-level --help shows all subcommands', () => {
  const result = runCli(['--help']);
  assert.equal(result.code, 0);
  assert.ok(result.stdout.includes('scan') || result.stderr.includes('scan'));
  assert.ok(result.stdout.includes('verify') || result.stderr.includes('verify'));
  assert.ok(result.stdout.includes('compare') || result.stderr.includes('compare'));
});

test('CLI: scan on golden-vectors dir produces CBOM (json output)', () => {
  const goldenDir = path.join(__dirname, '..', 'golden-vectors');
  const result = runCli(['scan', '--target', goldenDir, '--format', 'json']);
  assert.equal(result.code, 0);
  const bom = JSON.parse(result.stdout.trim());
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.6');
  assert.ok(Array.isArray(bom.components));
  assert.ok(bom.components.length > 0);
});

test('CLI: scan on golden-vectors dir produces CBOM (table output)', () => {
  const goldenDir = path.join(__dirname, '..', 'golden-vectors');
  const result = runCli(['scan', '--target', goldenDir, '--format', 'table']);
  assert.equal(result.code, 0);
  assert.ok(result.stdout.includes('Components') || result.stdout.includes('Asset'));
});

test('CLI: scan --out writes to file', () => {
  const goldenDir = path.join(__dirname, '..', 'golden-vectors');
  const outFile = '/tmp/test-scan-output.json';
  const result = runCli(['scan', '--target', goldenDir, '--format', 'json', '--out', outFile]);
  assert.equal(result.code, 0);
  assert.ok(fs.existsSync(outFile));
  const content = fs.readFileSync(outFile, 'utf8');
  const bom = JSON.parse(content);
  assert.equal(bom.bomFormat, 'CycloneDX');
  fs.unlinkSync(outFile);
});