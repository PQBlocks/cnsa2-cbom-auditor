'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

// Load golden vector DER bytes for testing (must be byte-identical to golden-vectors/certs/)
const GOLDEN_PATH = path.join(__dirname, '..', 'golden-vectors', 'certs');

// Define the fixtures required by S-02, corresponding to the 11 golden certs.
const loadFixture = (filename) => {
    const fullPath = path.join(GOLDEN_PATH, filename);
    if (!fs.existsSync(fullPath)) {
        throw new Error(`Fixture file not found: ${fullPath}. Check golden-vectors/certs/.`);
    }
    const buf = fs.readFileSync(fullPath);
    const text = buf.toString('utf8');
    if (text.includes('-----BEGIN')) {
        const b64 = text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
        return Buffer.from(b64, 'base64');
    }
    return buf;
};

const fixtures = {
    'mldsa65.crt': loadFixture('mldsa65.crt'),
    'rsa2048-sha256.crt': loadFixture('rsa2048-sha256.crt'),
    'mldsa44.crt': loadFixture('mldsa44.crt'),
    'mldsa87.crt': loadFixture('mldsa87.crt'),
    'slhdsa-sha2-128s.crt': loadFixture('slhdsa-sha2-128s.crt'),
    'slhdsa-shake-256f.crt': loadFixture('slhdsa-shake-256f.crt'),
    'ec-p256-sha256.crt': loadFixture('ec-p256-sha256.crt'),
    'ec-p384-sha384.crt': loadFixture('ec-p384-sha384.crt'),
    'ed25519.crt': loadFixture('ed25519.crt'),
    'rsa3072-sha384.crt': loadFixture('rsa3072-sha384.crt'),
    'rsa4096-sha512.crt': loadFixture('rsa4096-sha512.crt'),
};

// --- Test Suite for Hardening (Spec Requirement) ---
test('S-02: Hardening Test - mldsa65.crt DER parses correctly and without error', () => {
    const derBytes = fixtures['mldsa65.crt'];
    const { parseDer } = require('../lib/der.js');
    const ast = parseDer(derBytes);
    assert.ok(ast, 'mldsa65.crt must parse to an AST.');
});

test('S-02: Hardening Test - all 11 golden certs parse without error', () => {
    const { parseDer } = require('../lib/der.js');
    for (const [name, derBytes] of Object.entries(fixtures)) {
        const ast = parseDer(derBytes);
        assert.ok(ast, `${name} must parse to an AST.`);
    }
});

module.exports = { fixtures };