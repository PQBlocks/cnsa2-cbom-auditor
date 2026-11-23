#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { compareCboms, renderCompareTable } = require('../lib/compare');

const EXIT_OK = 0;
const EXIT_USAGE = 4;
const EXIT_INTERNAL = 1;

function usage() {
  return [
    'Usage: compare --before <file> --after <file> [--format json|table] [--out <file>]',
    '',
    'Options:',
    '  --before <file>   First CBOM file to compare',
    '  --after <file>    Second CBOM file to compare',
    '  --format <type>   Output format: json or table (default: table)',
    '  --out <file>      Write output to file instead of stdout',
    '  --help            Show this help message',
    '  --version         Show version',
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

  const beforeFile = args.before;
  const afterFile = args.after;
  const format = args.format || 'table';

  if (!beforeFile || !afterFile) {
    console.error('Error: --before and --after are required for compare');
    console.error(usage());
    process.exit(EXIT_USAGE);
  }

  const formatArg = args.format || 'table';
  if (formatArg !== 'json' && formatArg !== 'table') {
    console.error(`Error: unsupported --format "${formatArg}" (expected json|table)`);
    process.exit(EXIT_USAGE);
  }

  try {
    const result = compareCboms(beforeFile, afterFile);
    
    let output;
    if (format === 'table') {
      output = renderCompareTable(result);
    } else {
      output = JSON.stringify(result, null, 2);
    }

    if (args.out) {
      fs.writeFileSync(args.out, output, 'utf8');
    } else {
      console.log(output);
    }

    process.exit(EXIT_OK);
  } catch (err) {
    if (err && (err.code === 'ENOENT' || err.code === 'ENOTDIR')) {
      console.error(`Error: CBOM file not found`);
      process.exit(EXIT_INTERNAL);
    }
    console.error(err.message || err);
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
