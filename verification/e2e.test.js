import fs from 'node:fs';
import path from 'node:path';
import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import pkgScan from '../lib/scan.js';
import pkgVerify from '../lib/verify.js';

const scan = pkgScan.scan || pkgScan.scanToCbom;
const verifyCbom = pkgVerify.verifyCbom || pkgVerify;

describe('End-to-end integration test', () => {
  // Test: scan golden-vectors directory → CBOM → verify → schema OK, classifications match oracle exactly
  test('scan golden-vectors → CBOM → verify → schema + classifications match', async () => {
    const result = await scan('./golden-vectors');
    
    // Verify schema validation passes
    verifyCbom(result.bom);
    
    // Verify classifications match OpenSSL oracle (check each component against expected-classification.json)
    const expectedPath = path.join(process.cwd(), 'golden-vectors/expected/expected-classification.json');
    const expected = JSON.parse(fs.readFileSync(expectedPath, 'utf8'));
    
    // Check each certificate asset matches expected classification
    const certAssets = result.bom.components.filter(c => c.cryptoProperties.assetType === 'certificate');
    for (const cert of certAssets) {
      const file = cert.name;
      const expectedAsset = expected.certificates.find(a => a.file === `certs/${file}`);
      
      if (expectedAsset) {
        if (expectedAsset.signatureAlgorithm && typeof expectedAsset.signatureAlgorithm === 'object' && expectedAsset.signatureAlgorithm.oid) {
          assert.strictEqual(cert.cryptoProperties.oid, expectedAsset.signatureAlgorithm.oid, 
            `OID mismatch for ${file}: expected ${expectedAsset.signatureAlgorithm.oid}, got ${cert.cryptoProperties.oid}`);
        }
        if (expectedAsset.signature) {
          assert.strictEqual(cert.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 
            expectedAsset.signature.nistQuantumSecurityLevel, 
            `NIST level mismatch for ${file}: expected ${expectedAsset.signature.nistQuantumSecurityLevel}, got ${cert.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel}`);
          if (expectedAsset.signature.paramSetIdentifier) {
            assert.strictEqual(cert.cryptoProperties.algorithmProperties.parameterSetIdentifier, 
              expectedAsset.signature.paramSetIdentifier, 
              `ParamSet mismatch for ${file}: expected ${expectedAsset.signature.paramSetIdentifier}, got ${cert.cryptoProperties.algorithmProperties.parameterSetIdentifier}`);
          }
        }
      }
    }
    
    // Verify SPKI assets match expected classification
    const spkiAssets = result.bom.components.filter(c => c.cryptoProperties.assetType === 'algorithm');
    for (const spki of spkiAssets) {
      const file = spki.name;
      const expectedAsset = expected.keys.find(a => a.file === `spki/${file}`);
      
      if (expectedAsset) {
        assert.strictEqual(spki.cryptoProperties.oid, expectedAsset.oid, 
          `SPKI OID mismatch for ${file}: expected ${expectedAsset.oid}, got ${spki.cryptoProperties.oid}`);
      }
    }
  });
  
  test('scan → CBOM structure matches CycloneDX 1.6 schema', async () => {
    const result = await scan('./golden-vectors');
    
    // Required top-level fields per CycloneDX 1.6
    assert.strictEqual(result.bom.bomFormat, 'CycloneDX');
    assert.strictEqual(result.bom.specVersion, '1.6');
    assert.ok(result.bom.serialNumber);
    assert.strictEqual(typeof result.bom.version, 'number');
    assert.ok(result.bom.components && Array.isArray(result.bom.components));
    assert.ok(result.bom.metadata);
    assert.ok(result.bom.metadata.tools);
    assert.ok(result.bom.metadata.timestamp);
    
    // Verify components have required structure
    for (const component of result.bom.components) {
      assert.strictEqual(component.type, 'cryptographic-asset');
      assert.ok(component['bom-ref']);
      assert.ok(component.name);
      assert.ok(component.cryptoProperties);
      assert.ok(component.cryptoProperties.assetType);
      assert.ok(['algorithm', 'certificate', 'protocol', 'related-crypto-material'].includes(component.cryptoProperties.assetType));
      assert.ok(component.cryptoProperties.oid !== undefined);
    }
  });
  
  test('scan + verify produces deterministic output', async () => {
    const result1 = await scan('./golden-vectors');
    const result2 = await scan('./golden-vectors');
    
    // Compare CBOM content (serialNumber may differ, but everything else should be identical)
    const cbom1 = JSON.parse(JSON.stringify(result1.bom));
    const cbom2 = JSON.parse(JSON.stringify(result2.bom));
    
    // Remove volatile fields for deterministic comparison
    delete cbom1.serialNumber;
    delete cbom2.serialNumber;
    if (cbom1.metadata) delete cbom1.metadata.timestamp;
    if (cbom2.metadata) delete cbom2.metadata.timestamp;
    
    assert.deepStrictEqual(cbom1, cbom2, 'CBOM outputs are not deterministic');
  });
});