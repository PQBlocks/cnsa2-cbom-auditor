'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.dirname(__dirname);
const README_PATH = path.join(ROOT, 'README.md');
const DOCS_DIR = path.join(ROOT, 'lib', 'docs');
const API_DOCS_PATH = path.join(DOCS_DIR, 'api.md');

test('S-19: README.md exists and contains required sections', () => {
  assert.ok(fs.existsSync(README_PATH), 'README.md must exist');
  const readme = fs.readFileSync(README_PATH, 'utf8');
  assert.ok(readme.length > 200, 'README.md must not be a stub');

  // CLI usage documentation
  assert.ok(readme.includes('scan'), 'README.md must document scan command');
  assert.ok(readme.includes('verify'), 'README.md must document verify command');
  assert.ok(readme.includes('compare'), 'README.md must document compare command');

  // API examples
  assert.ok(readme.includes('API') || readme.includes('Usage'), 'README.md must document API usage');
  assert.ok(readme.includes('scanTarget') || readme.includes('scanToCbom') || readme.includes('scan'), 'README.md must include scan API');

  // Exit codes
  assert.ok(readme.includes('Exit Code') || readme.includes('exit code'), 'README.md must document exit codes');
  assert.ok(readme.includes('0') && readme.includes('1'), 'README.md must specify exit codes 0 and 1');

  // CBOM schema link
  assert.ok(
    readme.includes('CycloneDX') || readme.includes('cyclonedx') || readme.includes('cbom'),
    'README.md must reference CycloneDX CBOM schema'
  );
});

test('S-19: lib/docs/ output exists with API documentation', () => {
  assert.ok(fs.existsSync(DOCS_DIR), 'lib/docs directory must exist');
  assert.ok(fs.existsSync(API_DOCS_PATH), 'lib/docs/api.md must exist');
  const docs = fs.readFileSync(API_DOCS_PATH, 'utf8');
  assert.ok(docs.includes('scan') || docs.includes('cbom'), 'API docs must document key functions');
});
