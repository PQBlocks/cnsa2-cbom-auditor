'use strict';

// S-16: Verify subcommand (CBOM schema + finding check)
// Public API: verifyCbom(cbomPath | json | object, options?) -> { valid, bom, findings }

const fs = require('fs');
const { validateCbom } = require('./cbom.js');
const { findingsAtOrAbove } = require('./scan.js');

function readCbom(input) {
  let doc;
  if (Buffer.isBuffer(input)) input = input.toString('utf8');
  if (typeof input === 'string') {
    // If it points at an existing file, read it; otherwise treat as JSON text.
    try {
      if (fs.existsSync(input)) {
        doc = JSON.parse(fs.readFileSync(input, 'utf8'));
      }
    } catch (_) {
      // fall through to JSON parse
    }
    if (!doc) {
      try {
        doc = JSON.parse(input);
      } catch (err) {
        const e = new Error('Invalid JSON: ' + err.message);
        e.code = 'INVALID_JSON';
        throw e;
      }
    }
  } else if (input && typeof input === 'object' && !Array.isArray(input)) {
    doc = input;
  } else {
    const e = new TypeError('verifyCbom expects a file path, JSON string, or object');
    e.code = 'E_TYPE';
    throw e;
  }

  if (doc && doc.bom && doc.bom.bomFormat === 'CycloneDX') {
    return doc.bom;
  }
  if (doc && (doc.cbom || doc.summary || doc.classifications)) {
    const { cbom, summary, classifications, target, ...pureBom } = doc;
    if (pureBom.bomFormat === 'CycloneDX') {
      return pureBom;
    }
  }
  return doc;
}

function normalizeFindings(bom) {
  if (Array.isArray(bom.findings)) return bom.findings;
  // Some callers may attach findings under a different key.
  if (Array.isArray(bom.findingsArray)) return bom.findingsArray;
  return [];
}

function normalizeVerdict(finding) {
  if (!finding || typeof finding !== 'object') return 'unknown';
  if (finding.verdict) return finding.verdict;
  if (finding.severity === 'error') return 'disallowed';
  if (finding.severity === 'warning') return 'deprecated';
  if (finding.severity === 'info') return 'unknown';
  return 'unknown';
}

function verifyCbom(input, options = {}) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    const e = new TypeError('verifyCbom options must be an object');
    e.code = 'E_TYPE';
    throw e;
  }

  const bom = readCbom(input);

  // Schema validation (throws on failure).
  validateCbom(bom);

  const failOn = options.failOn || options['fail-on'] || null;
  const findings = normalizeFindings(bom).map((f) => {
    if (f && typeof f === 'object' && !f.verdict) {
      return Object.assign({}, f, { verdict: normalizeVerdict(f) });
    }
    return f;
  });

  if (failOn) {
    if (!['disallowed', 'deprecated', 'any'].includes(failOn)) {
      const e = new TypeError(`invalid --fail-on value: ${failOn} (expected disallowed|deprecated|any)`);
      e.code = 'E_TYPE';
      throw e;
    }
    const triggered = findingsAtOrAbove(findings, failOn);
    if (triggered.length > 0) {
      const err = new Error(`CBOM verification failed: ${triggered.length} finding(s) at or above "${failOn}"`);
      err.code = 'FINDINGS';
      err.findings = triggered;
      throw err;
    }
  }

  return { valid: true, bom, findings };
}

function validateCbomFile(filePath, options) {
  return verifyCbom(filePath, options);
}

module.exports = {
  verifyCbom,
  verify: verifyCbom,
  validateCbom,
  readCbom,
  validateCbomFile,
};