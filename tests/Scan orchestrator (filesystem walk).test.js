// tests/Scan orchestrator (filesystem walk).test.js
// S-09: Scan orchestrator (filesystem walk) - test file

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { scanTarget } from '../lib/scan.js';

describe('Scan orchestrator', () => {
  // Test that scanTarget can process the golden-vectors directory and return 23 assets
  test('should classify 23 assets from golden-vectors directory', async () => {
    const result = await scanTarget('./golden-vectors');
    
    // Should have 23 assets classified
    assert.strictEqual(result.assets.length, 23);
    
    // Should have findings for non-compliant assets (actual count depends on classification logic)
    assert.strictEqual(result.findings.length, 20);
    
    // Verify some specific asset classifications
    const ecP256Asset = result.assets.find(a => a.name === 'ec-p256-sha256.crt');
    assert.ok(ecP256Asset);
    assert.strictEqual(ecP256Asset.verdict, 'deprecated'); // From expected-classification.json
    
    const rsa2048Asset = result.assets.find(a => a.name === 'rsa2048-sha256.crt');
    assert.ok(rsa2048Asset);
    assert.strictEqual(rsa2048Asset.verdict, 'deprecated'); // From expected-classification.json
    
    const mldsa87Asset = result.assets.find(a => a.name === 'mldsa87.crt');
    assert.ok(mldsa87Asset);
    assert.strictEqual(mldsa87Asset.verdict, 'compliant'); // From expected-classification.json
  });
});