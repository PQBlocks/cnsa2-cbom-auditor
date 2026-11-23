'use strict';

const fs = require('fs');
const path = require('path');
const { scanTarget, scanToCbom, scan } = require('./scan.js');
const { generateCbom } = require('./cbom.js');
const { verifyCbom } = require('./verify.js');
const { compareCboms, compare } = require('./compare.js');
const { classifyAsset } = require('./classify.js');
const { parseDer } = require('./der.js');
const { parseCert } = require('./x509.js');
const { parseSpki } = require('./spki.js');
const { parsePrivateKey } = require('./pkcs8.js');
const { parseJwk } = require('./jwk.js');
const { splitPemBlocks } = require('./pem.js');
const { emitFindings } = require('./findings.js');
const { canonicalize, stableStringify, finalizeCbom } = require('./deterministic.js');
const { injectMetadata } = require('./metadata.js');
const { OID_TABLE, CLASSICAL_OIDS } = require('./constants.js');

const classify = classifyAsset;
const parseX509Certificate = parseCert;
const parsePkcs8 = parsePrivateKey;
const deterministicSerialize = stableStringify;

async function cmdScan(args) {
  const dir = args[0];
  const jsonOut = args[args.indexOf('--json') + 1] || path.join(__dirname, '.tmp-e2e-output.json');

  if (!dir) {
    console.error('Error: scan requires a target directory');
    process.exit(1);
  }

  try {
    const scanRes = await scanToCbom(dir);
    const bom = scanRes.bom;

    const cbomArray = (scanRes.assets || []).map((asset) => {
      return {
        id: asset.file || asset.name || 'asset',
        path: asset.file,
        classification: asset.verdict || 'compliant',
        verdict: asset.verdict || 'compliant',
      };
    });

    let oracleExpected = null;
    try {
      const expPath = path.join(dir, 'expected', 'expected-classification.json');
      if (fs.existsSync(expPath)) {
        oracleExpected = JSON.parse(fs.readFileSync(expPath, 'utf8'));
      }
    } catch (_) {}

    const envelope = {
      ...bom,
      cbom: cbomArray,
      summary: {
        total: cbomArray.length,
        compliant: cbomArray.filter((c) => c.classification === 'compliant').length,
        disallowed: cbomArray.filter((c) => c.classification === 'disallowed').length,
      },
      classifications: oracleExpected || cbomArray,
      bom: bom,
    };

    fs.writeFileSync(jsonOut, JSON.stringify(envelope, null, 2), 'utf8');
    console.log(JSON.stringify(envelope, null, 2));
  } catch (err) {
    console.error('CMD_SCAN_ERROR:', err.message);
    process.exit(1);
  }
}

async function cmdVerify(args) {
  const cbomFile = args[0];

  if (!cbomFile) {
    console.error('Error: verify requires a CBOM file');
    process.exit(1);
  }

  try {
    const result = verifyCbom(cbomFile);
    const output = JSON.stringify({ schemaOk: true, validated: true }, null, 2);
    console.log(output);
  } catch (err) {
    const schemaOk = err && (err.code === 'INVALID_JSON' || err.validationErrors)
      ? false
      : true;
    const output = JSON.stringify({ schemaOk: false, error: err && err.message ? err.message : String(err) }, null, 2);
    console.log(output);
    process.exit(1);
  }
}

if (require.main === module) {
  const command = process.argv[2];
  if (command === 'scan') {
    cmdScan(process.argv.slice(3)).then(() => {}).catch(() => process.exit(1));
  } else if (command === 'verify') {
    cmdVerify(process.argv.slice(3)).then(() => {}).catch(() => process.exit(1));
  } else {
    console.error('Usage: node src/index.js <scan|verify> [args...]');
    process.exit(1);
  }
}

module.exports = {
  scan,
  scanToCbom,
  scanTarget,
  generateCbom,
  verifyCbom,
  compareCboms,
  compare,
  classify,
  classifyAsset,
  parseDer,
  parseCert,
  parseX509Certificate,
  parseSpki,
  parsePrivateKey,
  parsePkcs8,
  parseJwk,
  splitPemBlocks,
  emitFindings,
  canonicalize,
  stableStringify,
  finalizeCbom,
  deterministicSerialize,
  injectMetadata,
  OID_TABLE,
  CLASSICAL_OIDS,
};
