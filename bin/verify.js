#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { verifyCbom } = require('../lib/verify.js');

const EXIT_OK = 0;
const EXIT_FINDINGS = 3;
const EXIT_USAGE = 4;
const EXIT_INTERNAL = 1;

function usage() {
  return [
    'Usage: verify --cbom <file> [--fail-on <disallowed|deprecated|any>]',
    '',
    'Options:',
    '  --cbom <file>   CBOM file to validate',
    '  --fail-on ...   Fail when findings at or above the given level',
    '  --help          Show this help message',
    '  --version       Show version',
  ].join('\n');
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      args.help = true;
    } else if (arg === '--version' || arg === '-v') {
      args.version = true;
    } else if (arg === 'verify') {
      args._.push(arg);
    } else if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        args[key] = next;
        i++;
      } else {
        args[key] = true;
      }
    } else {
      args._.push(arg);
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const pkg = require('../package.json');

  if (args.help) {
    console.log(usage());
    process.exit(EXIT_OK);
  }

  if (args.version) {
    console.log(pkg.version);
    process.exit(EXIT_OK);
  }

  // Accept `verify` as an optional leading subcommand for compatibility.
  let cbomFile = args.cbom;
  if (!cbomFile) {
    const positional = args._.filter((x) => x !== 'verify');
    if (positional.length > 0) cbomFile = positional[0];
  }

  if (!cbomFile) {
    console.error('Error: --cbom is required for verify');
    console.error(usage());
    process.exit(EXIT_USAGE);
  }

  const failOn = args['fail-on'];
  if (failOn && !['disallowed', 'deprecated', 'any'].includes(failOn)) {
    console.error(`Error: unsupported --fail-on "${failOn}" (expected disallowed|deprecated|any)`);
    process.exit(EXIT_USAGE);
  }

  try {
    verifyCbom(cbomFile, { failOn });
    console.log('CBOM is valid');
    process.exit(EXIT_OK);
  } catch (err) {
    if (err && (err.code === 'ENOENT' || err.code === 'ENOTDIR')) {
      console.error(`Error: CBOM file not found: ${cbomFile}`);
      process.exit(EXIT_INTERNAL);
    }
    if (err && err.code === 'INVALID_JSON') {
      console.error(err.message);
      process.exit(EXIT_INTERNAL);
    }
    if (err && err.code === 'FINDINGS') {
      console.error(err.message);
      process.exit(EXIT_FINDINGS);
    }
    // Schema validation errors and others
    if (err && err.validationErrors) {
      console.error('Invalid CBOM: ' + JSON.stringify(err.validationErrors));
      process.exit(EXIT_FINDINGS);
    }
    console.error(err && err.message ? err.message : err);
    // Treat schema validation failure as findings exit (non-zero)
    if (err && /schema validation/i.test(String(err.message))) {
      process.exit(EXIT_FINDINGS);
    }
    process.exit(EXIT_INTERNAL);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err && err.message ? err.message : err);
    process.exit(EXIT_INTERNAL);
  });
}

module.exports = { main, parseArgs };