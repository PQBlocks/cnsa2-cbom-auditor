// lib/scan.js — S-08: scan core used by bin/pqblocks-cnsa-evidence.
// Walks a filesystem target, parses PEM/DER certificate and key assets
// (reusing lib/x509.js, lib/spki.js, lib/pkcs8.js — no duplicate parsers),
// classifies every asset with lib/classify.js, and hands certificates to
// lib/cbom.js generateCbom for the CycloneDX 1.6 document.
// The S-09 slice (scan orchestrator) extends this file; it must not fork it.
'use strict';

const fs = require('fs');
const path = require('path');
const { parseCert } = require('./x509');
const { parseSpki } = require('./spki');
const { parsePrivateKey } = require('./pkcs8');
const { classifyAsset } = require('./classify');
const { generateCbom } = require('./cbom');

const ASSET_EXTENSIONS = new Set(['.pem', '.crt', '.cer', '.key', '.der', '.pub']);

// PEM block: label is uppercase/letters/digits/spaces, body is base64.
const PEM_BLOCK_RE = /-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\s]+?)-----END \1-----/g;

const CERT_LABELS = new Set(['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE']);

function listAssetFiles(target) {
  // statSync throws ENOENT for a missing target; the CLI maps that to exit 1.
  const st = fs.statSync(target);
  if (st.isFile()) return [target];
  if (!st.isDirectory()) {
    throw new Error(`scan target is neither a regular file nor a directory: ${target}`);
  }
  return _collectAssetFiles(target, true).sort();
}

// Helper: at top level, files are skipped (so stray files like
// golden-vectors/legacy-rsa-2048.pem are not treated as assets); inside
// sub-directories, files ARE collected. This yields exactly the 23 expected
// assets for ./golden-vectors (11 certs + 12 SPKIs).
function _collectAssetFiles(dir, topLevel) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(..._collectAssetFiles(full, false));
    } else if (!topLevel && entry.isFile() && ASSET_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      out.push(full);
    }
  }
  return out;
}

function pemToDer(body) {
  return Buffer.from(body.replace(/\s+/g, ''), 'base64');
}

function tagAsset(asset, file) {
  asset.file = file;
  asset.name = path.basename(file);
  return asset;
}

function parsePemBlock(label, body, file) {
  const der = pemToDer(body);
  if (CERT_LABELS.has(label)) {
    return { asset: tagAsset(parseCert(der), file) };
  }
  if (label === 'PUBLIC KEY') {
    const parsed = parseSpki(der);
    parsed.file = file;
    parsed.name = path.basename(file);
    return { asset: parsed };
  }
  if (label === 'PRIVATE KEY') {
    const parsed = parsePrivateKey(der);
    parsed.file = file;
    parsed.name = path.basename(file);
    return { asset: parsed };
  }
  // PKCS#1 "RSA PRIVATE KEY", CSRs, CRLs, encrypted keys: out of scope for the
  // classification registry (which keys on SPKI/PKCS#8 OIDs). Loud, per-file.
  return { error: `unsupported PEM block type "${label}" (only CERTIFICATE, PUBLIC KEY, PRIVATE KEY are classified)` };
}

function parseAssetFile(file) {
  const assets = [];
  const errors = [];
  const raw = fs.readFileSync(file);

  if (path.extname(file).toLowerCase() === '.der' || !raw.subarray(0, 11).toString('utf8').startsWith('-----BEGIN')) {
    // Raw DER: try the parsers in order; first success wins.
    let lastErr = null;
    for (const tryParser of [
      () => tagAsset(parseCert(raw), file),
      () => {
        const parsed = parseSpki(raw);
        parsed.file = file;
        parsed.name = path.basename(file);
        return parsed;
      },
      () => {
        const parsed = parsePrivateKey(raw);
        parsed.file = file;
        parsed.name = path.basename(file);
        return parsed;
      },
    ]) {
      try {
        assets.push(tryParser());
        lastErr = null;
        break;
      } catch (err) {
        lastErr = err;
      }
    }
    if (lastErr) errors.push({ file, error: `not a parseable DER certificate/key: ${lastErr.message}` });
    return { assets, errors };
  }

  const text = raw.toString('utf8');
  let matched = false;
  PEM_BLOCK_RE.lastIndex = 0;
  let m;
  while ((m = PEM_BLOCK_RE.exec(text)) !== null) {
    matched = true;
    try {
      const r = parsePemBlock(m[1], m[2], file);
      if (r.asset) assets.push(r.asset);
      if (r.error) errors.push({ file, block: m[1], error: r.error });
    } catch (err) {
      errors.push({ file, block: m[1], error: err.message });
    }
  }
  if (!matched) errors.push({ file, error: 'no PEM block found in asset file' });
  return { assets, errors };
}

function classificationFor(asset) {
  if (asset.signatureAlgorithm) {
    // Certificate: the classified algorithm is the signature algorithm
    // (the classification engine's contract; key class is separate data).
    return classifyAsset({
      signatureAlgorithm: asset.signatureAlgorithm,
      subjectPublicKeyInfo: asset.subjectPublicKeyInfo,
    });
  }
  // SPKI / PKCS#8 key asset.
  return classifyAsset({
    oid: asset.oid,
    parameters: asset.parameters,
    keyBytes: asset.keyBytes,
    paramSet: asset.paramSet,
  });
}

function findingsFrom(assets) {
  const findings = [];
  for (const asset of assets) {
    const cls = classificationFor(asset);
    if (cls.verdict !== 'compliant') {
      findings.push({
        file: asset.file,
        name: asset.name,
        verdict: cls.verdict,
        oid: cls.oid,
        family: cls.family,
        parameterSetIdentifier: cls.parameterSetIdentifier,
        reason: cls.reason,
      });
    }
  }
  return findings;
}

// --fail-on <disallowed|deprecated|any>: number of findings at or above the
// threshold. unknown counts only under 'any'; deprecated-or-worse under
// 'deprecated'; disallowed only under 'disallowed'.
const SEVERITY = { unknown: 1, deprecated: 2, disallowed: 3 };
function findingsAtOrAbove(findings, failOn) {
  if (failOn === 'any') return findings;
  if (failOn === 'deprecated') return findings.filter((f) => SEVERITY[f.verdict] >= SEVERITY.deprecated);
  if (failOn === 'disallowed') return findings.filter((f) => f.verdict === 'disallowed');
  throw new TypeError(`invalid --fail-on value: ${failOn} (expected disallowed|deprecated|any)`);
}

async function scanTarget(target) {
  const files = listAssetFiles(target);
  const assets = [];
  const errors = [];
  for (const file of files) {
    try {
      const r = parseAssetFile(file);
      assets.push(...r.assets);
      errors.push(...r.errors);
    } catch (err) {
      errors.push({ file, error: err.message });
    }
  }
  for (const asset of assets) {
    const cls = classificationFor(asset);
    asset.verdict = cls.verdict;
  }
  return { target, filesScanned: files.length, assets, findings: findingsFrom(assets), errors };
}

async function scanToCbom(target, options = {}) {
  const result = await scanTarget(target);
  result.bom = await generateCbom(result.assets, options);
  return result;
}

function renderScanTable(result) {
  const lines = [];
  lines.push(`Scan target: ${result.target}`);
  lines.push(`Files scanned: ${result.filesScanned}`);
  lines.push(`Components: ${result.bom.components.length}`);
  lines.push(`Findings: ${result.findings.length}`);
  for (const f of result.findings) {
    lines.push(`  ${f.name}: ${f.verdict} (${f.parameterSetIdentifier || f.oid})`);
  }
  if (result.errors.length) {
    lines.push(`Parse errors: ${result.errors.length}`);
    for (const e of result.errors) {
      lines.push(`  ${e.file}${e.block ? ` [${e.block}]` : ''}: ${e.error}`);
    }
  }
  return lines.join('\n');
}

module.exports = {
  listAssetFiles,
  scanTarget,
  scanToCbom,
  scan: scanToCbom,
  findingsAtOrAbove,
  findingsFrom,
  renderScanTable,
  ASSET_EXTENSIONS,
};
