import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const LANE_ROOT = process.cwd();
const SRC = path.join(LANE_ROOT, 'src');
const GOLDEN_VECTORS = path.join(LANE_ROOT, 'golden-vectors');
const TMP_OUT = path.join(LANE_ROOT, '.tmp-e2e-output.json');

function runScan(dir, jsonOut = TMP_OUT) {
  try {
    execFileSync('node', [path.join(SRC, 'index.js'), 'scan', dir, '--json', jsonOut], {
      stdio: 'ignore',
      timeout: 30000,
    });
    return JSON.parse(fs.readFileSync(jsonOut, 'utf8'));
  } catch (err) {
    throw new Error(`scan subcommand failed: ${err.message}`);
  }
}

describe('End-to-end integration test (S-18)', () => {
  test('scan golden-vectors dir -> CBOM -> verify -> schema OK, classifications match oracle exactly', () => {
    const scanResult = runScan(GOLDEN_VECTORS, TMP_OUT);

    assert.ok(scanResult, 'scan result must exist');
    assert.ok(Array.isArray(scanResult.cbom), 'cbom must be an array');
    assert.ok(scanResult.cbom.length > 0, 'cbom must be non-empty');
    assert.ok(scanResult.summary, 'scan summary must exist');

    // Every scanned asset must be classified
    for (const entry of scanResult.cbom) {
      assert.ok(entry.classification, `asset ${entry.path || entry.id} must carry a classification`);
    }

    // Verify subcommand accepts the CBOM output and reports schema OK
    const verifyResult = execFileSync(
      'node',
      [path.join(SRC, 'index.js'), 'verify', TMP_OUT],
      { encoding: 'utf8', stdio: 'pipe', timeout: 30000 }
    );
    const report = JSON.parse(verifyResult);
    assert.ok(report.schemaOk, `verify must report schemaOk; got: ${verifyResult.slice(0, 200)}`);

    // Classifications match oracle exactly: every asset's classification equals expected
    const expected = JSON.parse(
      fs.readFileSync(path.join(GOLDEN_VECTORS, 'expected', 'expected-classification.json'), 'utf8')
    );
    assert.deepStrictEqual(
      scanResult.classifications || scanResult.cbom.map(e => ({ id: e.id, classification: e.classification })),
      expected,
      'classifications must match oracle exactly'
    );

    fs.unlinkSync(TMP_OUT);
  });
});
