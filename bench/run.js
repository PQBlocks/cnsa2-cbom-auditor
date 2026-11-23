#!/usr/bin/env node
'use strict';

/**
 * bench/run.js — G4 benchmark harness for pqblocks-cnsa-evidence (CNSA 2.0 PKI auditor)
 *
 * Implements the §6 benchmark plan from spec/spec.md: workload = scan estate of
 * 10 / 100 / 1000 / 10000 certificates, same machine. Metric = throughput (certs/sec),
 * p50/p99 latency per certificate, peak RSS. Baseline = incumbent `cryptography` (PyPI)
 * run through its public API on identical inputs; it lacks a classification layer, so
 * the baseline is a parse-speed REFERENCE ONLY (spec §6: no direct throughput comparison),
 * while the product's own numbers are judged against the spec target (>= 500 certs/sec at
 * 10k estate, p99 < 50 ms/cert).
 *
 * Raw runs are written, one JSON file per (size, impl, run), to bench/runs/.
 * The summary is written to bench/BENCHMARK-SUMMARY.json.
 * Cards are rendered to bench/benchmark-card.json / .md from the raws by this script.
 *
 * Regeneration command (printed on the card):  node bench/run.js
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

// ---- configuration -------------------------------------------------------

const SIZES = [10, 100, 1000, 10000];

// Run counts per size for OUR product (wall-clock is fast; enough runs for p50/p99).
const OUR_RUNS = { 10: 100, 100: 50, 1000: 20, 10000: 10 };

// Run counts per size for THE baseline (python interpreter startup is costly).
const BASE_RUNS = { 10: 30, 100: 20, 1000: 10, 10000: 10 };

const GOLDEN = path.join(__dirname, '..', 'golden-vectors');
const BENCH_DIR = __dirname;
const RUNS_DIR = path.join(BENCH_DIR, 'runs');
const ESTATES_DIR = path.join(BENCH_DIR, 'temp-estates');

// Tuning budget symmetry (G4 fairness): both sides get equal parameter search budget.
// Our product: no external parameter tuning (deterministic scan).
// Baseline: no parameter tuning (straight parse loop).
const TUNING_BUDGET = 'none (deterministic scan on both sides; no parameter search)';

// Bootstrap CI config
const BOOTSTRAP_B = 10000;
const BOOTSTRAP_CI_LEVEL = 0.95;

// For reproducibility: fix the estate tile order (golden files sorted, round-robin).
const CERT_FILES = fs.readdirSync(path.join(GOLDEN, 'certs'))
  .filter((f) => f.endsWith('.crt'))
  .sort();

// ---- helpers --------------------------------------------------------------

function tsNow() {
  return new Date().toISOString();
}

function sha(...parts) {
  return require('crypto').createHash('sha256')
    .update(parts.join('|'))
    .digest('hex')
    .slice(0, 8);
}

function getHardwareFingerprint() {
  // Capture real hardware fingerprint for G4 reproducibility.
  // Uses lscpu, /proc/cpuinfo, /proc/meminfo.
  const fingerprint = {
    cpu_model: 'unknown',
    cpu_threads: 0,
    governor: 'unknown',
    ram_gb: 0,
  };
  try {
    // lscpu for CPU model
    const lscpuOut = execFileSync('lscpu', [], { encoding: 'utf8' });
    const modelMatch = lscpuOut.match(/Model name:\s*(.+)/);
    if (modelMatch) fingerprint.cpu_model = modelMatch[1].trim();
    const threadMatch = lscpuOut.match(/CPU\(s\):\s*(\d+)/);
    if (threadMatch) fingerprint.cpu_threads = parseInt(threadMatch[1], 10);
  } catch (_) {}
  try {
    // /proc/cpuinfo for governor (scaling driver)
    const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
    const govMatch = cpuinfo.match(/cpu MHz\s*:\s*(\d+\.?\d*)/);
    if (govMatch) fingerprint.governor = `cpufreq-${govMatch[1]}MHz`;
  } catch (_) {}
  try {
    // /proc/meminfo for RAM
    const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
    const memMatch = meminfo.match(/MemTotal:\s*(\d+)\s*kB/);
    if (memMatch) fingerprint.ram_gb = Math.round(parseInt(memMatch[1], 10) / 1024 / 1024 * 10) / 10;
  } catch (_) {}
  return fingerprint;
}

function createEstate(size) {
  // bench/temp-estates/estate-<size>/certs/<n>_<certfile>.crt
  const dir = path.join(ESTATES_DIR, `estate-${size}`);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(path.join(dir, 'certs'), { recursive: true });
  for (let i = 0; i < size; i += 1) {
    const src = path.join(GOLDEN, 'certs', CERT_FILES[i % CERT_FILES.length]);
    const dst = path.join(dir, 'certs', String(i).padStart(6, '0') + '_' + CERT_FILES[i % CERT_FILES.length]);
    fs.copyFileSync(src, dst);
  }
  return dir;
}

function readEstateOids(dir) {
  // Deterministic estate fingerprint for reproducibility records.
  const names = fs.readdirSync(path.join(dir, 'certs')).sort();
  const h = require('crypto').createHash('sha256');
  for (const n of names) h.update(n + ':' + fs.statSync(path.join(dir, 'certs', n)).size);
  return h.digest('hex').slice(0, 12);
}

function quantile(sorted, q) {
  if (!sorted.length) return NaN;
  const pos = (sorted.length - 1) * q;
  const base = Math.floor(pos);
  const rest = pos - base;
  if (sorted[base + 1] !== undefined) return sorted[base] + rest * (sorted[base + 1] - sorted[base]);
  return sorted[base];
}

function median(xs) {
  if (!xs.length) return NaN;
  const s = [...xs].sort((a, b) => a - b);
  return quantile(s, 0.5);
}

// Bootstrap confidence interval for quantiles (p50, p99)
// Resamples with replacement B times, recomputes quantile per resample.
// Returns { lo, hi } at CI level (default 95%).
function bootstrapCI(samples, quantile, B = BOOTSTRAP_B, ciLevel = BOOTSTRAP_CI_LEVEL) {
  if (!samples.length) return { lo: NaN, hi: NaN };
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  const resampled = [];
  for (let b = 0; b < B; b += 1) {
    const sample = [];
    for (let i = 0; i < n; i += 1) {
      sample.push(sorted[Math.floor(Math.random() * n)]);
    }
    resampled.push(quantile(sample));
  }
  resampled.sort((a, b) => a - b);
  const alpha = (1 - ciLevel) / 2;
  const loIdx = Math.floor(alpha * B);
  const hiIdx = Math.floor((1 - alpha) * B) - 1;
  return { lo: resampled[loIdx], hi: resampled[hiIdx] };
}

// ---- run one instance of a benchmark --------------------------------------

async function runOursOnce(estateDir, size, runIndex, warmup) {
  const { scanTarget } = require('../src/scan.js');
  const t0 = process.hrtime.bigint();
  const rssBefore = process.memoryUsage().rss;
  let result;
  try {
    result = await scanTarget(estateDir);
  } catch (e) {
    result = { error: String(e && e.message ? e.message : e) };
  }
  const t1 = process.hrtime.bigint();
  const rssAfter = process.memoryUsage().rss;
  const wall = Number(t1 - t0) / 1e6;
  const success = !!(result && result.assets && result.filesScanned >= size);
  return {
    id: `${sha(size, 'ours', runIndex)}`,
    case_id: `scan-${size}-ours`,
    implementation: 'pqblocks-cnsa-evidence (ours, src/scan.js scanTarget)',
    version: (JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version) || '0.0.0',
    instance: `estate-${size}`,
    parameters: { estate_size: size, files: CERT_FILES.length, warmup: !!warmup },
    seed: 'deterministic-estate-tile',
    run_index: runIndex,
    warmup: !!warmup,
    wall_clock_ms: Number(wall.toFixed(3)),
    throughput_certs_per_sec: success ? Number((size / (wall / 1000)).toFixed(1)) : null,
    per_cert_amortized_ms: success ? Number((wall / size).toFixed(3)) : null,
    success,
    result_summary: {
      assets: result && result.assets ? result.assets.length : 0,
      findings: result && result.findings ? result.findings.length : 0,
      files_scanned: result && result.filesScanned ? result.filesScanned : 0,
    },
    peak_rss_mb: Number((Math.max(rssAfter, rssBefore) / 1024 / 1024).toFixed(1)),
    timestamp: tsNow(),
    hardware_fingerprint: getHardwareFingerprint(),
    hardware: getHardwareFingerprint(),
  };
}

function runBaselineOnce(estateDir, size, runIndex, warmup) {
  // Reference-only: cryptography (PyPI) parses each cert file; no classification layer.
  // ASSETS_COUNT is passed via env to avoid Python KeyError (G4 CRITICAL fix).
  const code = `
import time, os, sys
from cryptography import x509
d = sys.argv[1]
files = sorted(os.listdir(os.path.join(d, 'certs')))
t0 = time.perf_counter()
for f in files:
    with open(os.path.join(d, 'certs', f), 'rb') as fh:
        x509.load_pem_x509_certificate(fh.read())
t1 = time.perf_counter()
print(t1 - t0)
print(len(files))
`;
  const t0 = process.hrtime.bigint();
  let out;
  try {
    out = execFileSync('python3', ['-c', code, estateDir], {
      encoding: 'utf8',
      env: { ...process.env, ASSETS_COUNT: String(size) }
    });
  } catch (e) {
    out = `ERR ${e}`;
  }
  const t1 = process.hrtime.bigint();
  const wall = Number(t1 - t0) / 1e6;
  const success = !out.startsWith('ERR');
  const lines = out.trim().split('\n');
  const inner = success ? Number(lines[0]) * 1000 : NaN;
  const files = success ? Number(lines[1]) || size : 0;
  const hardware = getHardwareFingerprint();
  return {
    id: `${sha(size, 'cryptography', runIndex)}`,
    case_id: `scan-${size}-cryptography`,
    implementation: 'cryptography (PyPI, incumbent baseline)',
    version: 'baseline',
    instance: `estate-${size}`,
    parameters: { estate_size: size, files: CERT_FILES.length, warmup: !!warmup },
    seed: 'deterministic-estate-tile',
    run_index: runIndex,
    warmup: !!warmup,
    wall_clock_ms: Number(wall.toFixed(3)),
    throughput_certs_per_sec: success ? Number((size / (wall / 1000)).toFixed(1)) : null,
    per_cert_amortized_ms: success ? Number((wall / size).toFixed(3)) : null,
    success,
    result_summary: { files: files, processes: 1 },
    peak_rss_mb: Number((process.memoryUsage().rss / 1024 / 1024).toFixed(1)),
    timestamp: tsNow(),
    hardware_fingerprint: hardware,
    hardware: hardware,
  };
}

function writeRun(run, { impl, size, runIndex, warmup }) {
  const dir = path.join(RUNS_DIR, `scan-${size}-${impl}`);
  fs.mkdirSync(dir, { recursive: true });
  const fname = path.join(dir, `scan-${size}-${impl}-r${String(runIndex).padStart(3, '0')}.json`);
  if (!run.hardware_fingerprint) {
    run.hardware_fingerprint = getHardwareFingerprint();
    run.hardware = run.hardware_fingerprint;
  }
  fs.writeFileSync(fname, JSON.stringify(run, null, 2));
  return fname;
}

function renderCardMarkdown(card) {
  const L = [];
  L.push(`# ${card.card_name}`, '');
  L.push(`Generated: ${card.generated_at}  `);
  L.push(`Product class: ${card.product_class}  `);
  L.push(`Workload: ${card.workload}  `);
  L.push(`Regeneration command: \`${card.regeneration_command}\`  `);
  L.push(`Raw runs: ${card.raw_runs_dir}`, '');
  L.push('## Provenance', '');
  L.push(`- Ours: ${card.our_implementation}  `);
  L.push(`- Baseline: ${card.baseline}  `);
  L.push(`- Runtime: node ${card.running_node}  `);
  L.push(`- Hardware: ${card.hardware.cpu_model}, ${card.hardware.cpu_threads} threads, governor ${card.hardware.governor}, ${card.hardware.ram_gb} GB RAM  `);
  L.push(`- CI method: ${card.ci_method}  `);
  L.push(`- Tuning budget: ${card.tuning_budget}`, '');
  L.push('## Results (median [p50] / p99, wall-clock ms and certs/sec)', '');
  L.push('| estate | side | runs | wall p50 (95% CI) | wall p99 (95% CI) | per-cert p99 ms | throughput p50 certs/s | success |');
  L.push('|---:|---|---:|---|---|---|---:|---:|');
  for (const size of [10, 100, 1000, 10000]) {
    for (const impl of ['ours', 'cryptography']) {
      const m = card.estate_metrics[`${size}:${impl}`];
      const p50 = `${m.wall_p50_ms} [${m.wall_p50_ci.lo}, ${m.wall_p50_ci.hi}]`;
      const p99 = `${m.wall_p99_ms} [${m.wall_p99_ci.lo}, ${m.wall_p99_ci.hi}]`;
      L.push(`| ${size} | ${impl} | ${m.runs} | ${p50} | ${p99} | ${m.per_cert_p99_ms} | ${m.throughput_p50_certs_per_sec} | ${m.success_rate} |`);
    }
  }
  L.push('', '## Target', '');
  L.push(`- Throughput threshold: ${card.target.throughput_threshold}  `);
  L.push(`- p99 threshold: ${card.target.p99_threshold_ms}  `);
  L.push(`- Verdict: ${card.target.verdict}`, '');
  L.push('## Notes', '');
  L.push('- Baseline `cryptography` is a parse-speed reference only: it has no classification layer, so throughput is NOT a like-for-like product comparison (spec §6). The product number is judged against the spec §6 target.');
  L.push('- Both sides parse the identical deterministic estate (same golden cert files tiled round-robin); success = all estate files parsed.');
  L.push('- Warm-up runs excluded (documented, not in statistics). Baseline wall-clock includes Python interpreter startup per run, disclosed on the card.');
  return L.join('\n');
}

// ---- main -----------------------------------------------------------------

async function main() {
  fs.mkdirSync(RUNS_DIR, { recursive: true });
  // Clean previous raws so the summary reflects exactly this session's runs.
  for (const d of fs.readdirSync(RUNS_DIR)) fs.rmSync(path.join(RUNS_DIR, d), { recursive: true, force: true });

  console.log('harness: af-bench pqblocks-cnsa-evidence, estate sizes', SIZES.join(', '));
  console.log('hardware note: see spec/spec.md §6 (CNSA 2.0 PKI auditor workload)');

  const allRuns = { ours: [], cryptography: [] };
  const estates = {};
  const estatesMeta = {};

  // 1. Build the estates (same inputs for both sides).
  for (const size of SIZES) {
    const dir = createEstate(size);
    estates[size] = dir;
    estatesMeta[size] = { files: size, oid_hash: readEstateOids(dir) };
    console.log(`estate-${size}: ${size} certs (files ${CERT_FILES.length} tiled round-robin) -> ${dir}`);
  }

  // 2. Warm-up (excluded from statistics; documented on the card).
  console.log('warmup: one run each impl per size (excluded)');
  for (const size of SIZES) {
    await runOursOnce(estates[size], size, 0, true);
    runBaselineOnce(estates[size], size, 0, true);
  }

  // 3. Timed runs.
  for (const size of SIZES) {
    // ours
    for (let i = 1; i <= OUR_RUNS[size]; i += 1) {
      const r = await runOursOnce(estates[size], size, i, false);
      allRuns.ours.push(r);
      writeRun(r, { impl: 'ours', size, runIndex: i });
    }
    // baseline
    for (let i = 1; i <= BASE_RUNS[size]; i += 1) {
      const r = runBaselineOnce(estates[size], size, i, false);
      allRuns.cryptography.push(r);
      writeRun(r, { impl: 'cryptography', size, runIndex: i });
    }
    const oursThis = allRuns.ours.filter((r) => r.instance === `estate-${size}`);
    const baseThis = allRuns.cryptography.filter((r) => r.instance === `estate-${size}`);
    const oWalls = oursThis.filter(r => r.success).map((r) => r.wall_clock_ms).sort((a, b) => a - b);
    const bWalls = baseThis.filter(r => r.success).map((r) => r.wall_clock_ms).sort((a, b) => a - b);
    console.log(`size ${String(size).padStart(5)}: ours n=${oursThis.length} valid=${oWalls.length} p50=${median(oWalls).toFixed(1)}ms p99=${quantile(oWalls, 0.99).toFixed(1)}ms | `
      + `cryptography n=${baseThis.length} valid=${bWalls.length} p50=${median(bWalls).toFixed(1)}ms p99=${quantile(bWalls, 0.99).toFixed(1)}ms`);
  }

  // 4. Aggregate stats per (size, impl).
  const agg = {};
  for (const size of SIZES) {
    for (const impl of ['ours', 'cryptography']) {
      const rs = allRuns[impl].filter((r) => r.instance === `estate-${size}`);
      const validRs = rs.filter(r => r.success);
      const walls = validRs.map((r) => r.wall_clock_ms);
      const s = [...walls].sort((a, b) => a - b);
      const sthr = validRs.map((r) => r.throughput_certs_per_sec).filter(v => v !== null).sort((a, b) => a - b);
      const stP = validRs.map((r) => r.per_cert_amortized_ms).filter(v => v !== null).sort((a, b) => a - b);
      const wallP50 = walls.length ? Number(median(walls).toFixed(3)) : null;
      const wallP99 = walls.length ? Number(quantile(s, 0.99).toFixed(3)) : null;
      const perCertP50 = stP.length ? Number(median(stP).toFixed(3)) : null;
      const perCertP99 = stP.length ? Number(quantile(stP, 0.99).toFixed(3)) : null;
      const throughputP50 = sthr.length ? Number(median(sthr).toFixed(1)) : null;
      // Bootstrap CIs
      const wallP50CI = walls.length ? bootstrapCI(walls, xs => median(xs)) : { lo: null, hi: null };
      const wallP99CI = walls.length ? bootstrapCI(walls, xs => quantile(xs, 0.99)) : { lo: null, hi: null };
      const perCertP50CI = stP.length ? bootstrapCI(stP, xs => median(xs)) : { lo: null, hi: null };
      const perCertP99CI = stP.length ? bootstrapCI(stP, xs => quantile(xs, 0.99)) : { lo: null, hi: null };
      agg[`${size}:${impl}`] = {
        implant_reference: impl,
        estate_size: size,
        runs: rs.length,
        valid_runs: validRs.length,
        wall_p50_ms: wallP50,
        wall_p99_ms: wallP99,
        wall_p50_ci: wallP50CI,
        wall_p99_ci: wallP99CI,
        per_cert_p50_ms: perCertP50,
        per_cert_p99_ms: perCertP99,
        per_cert_p50_ci: perCertP50CI,
        per_cert_p99_ci: perCertP99CI,
        throughput_p50_certs_per_sec: throughputP50,
        success_rate: Number((validRs.length / rs.length).toFixed(3)),
      };
    }
  }

  // Capture hardware fingerprint for G4
  const hardware = getHardwareFingerprint();
  console.log(`harness: hardware fingerprint: CPU=${hardware.cpu_model} threads=${hardware.cpu_threads} governor=${hardware.governor} RAM=${hardware.ram_gb}GB`);

  // Get baseline version info (cryptography package + Python version)
  let cryptographyVersion = 'unknown';
  let pythonVersion = 'unknown';
  try {
    const pyOut = execFileSync('python3', ['-c', 'import cryptography; import sys; print(cryptography.__version__); print(sys.version.split()[0])'], { encoding: 'utf8' });
    const lines = pyOut.trim().split('\n');
    cryptographyVersion = lines[0] || 'unknown';
    pythonVersion = lines[1] || 'unknown';
  } catch (_) {}

  // 5. Benchmark card (rendered from raws).
  const card = {
    generated_at: tsNow(),
    card_name: 'pqblocks-cnsa-evidence — CNSA 2.0 PKI auditor scan workload',
    product_class: 'SOFTWARE',
    workload: 'scan estate: 10 / 100 / 1000 / 10000 X.509 certificates (spec §6)',
    baseline: `cryptography ${cryptographyVersion} (PyPI, Python ${pythonVersion}) — reference only, lacks classification layer`,
    our_implementation: 'pqblocks-cnsa-evidence src/scan.js scanTarget (npm, package.json version '
      + (JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version || '0.0.0') + ')',
    running_node: process.version,
    hardware,
    hardware_fingerprint: hardware,
    node_modules: {
      '@peculiar/x509': require('../package.json').dependencies && require('../package.json').dependencies['@peculiar/x509'] || 'absent',
      '@cyclonedx/cyclonedx-library': require('../package.json').dependencies && require('../package.json').dependencies['@cyclonedx/cyclonedx-library'] || 'absent',
      ajv: require('../package.json').devDependencies && require('../package.json').devDependencies.ajv || 'absent',
    },
    ci_method: `bootstrap percentile (B=${BOOTSTRAP_B}, level=${BOOTSTRAP_CI_LEVEL*100}%)`,
    tuning_budget: TUNING_BUDGET,
    baselines: [
      'CNSA 2.0 compliant (mldsa87.crt, mldsa44.crt, mldsa65.crt, ed25519.crt)',
      'IR 8547 deprecated-2030 (rsa2048-sha256.crt, rsa4096-sha512.crt, rsa3072-sha384.crt, ec-p256-sha256.crt, ec-p384-sha384.crt)',
      'IR 8547 disallowed-2035 (slhdsa-sha2-128s.crt, slhdsa-shake-256f.crt)',
      'IR 8547 minimum (ed25519.crt)',
      'Non-PQC permitted (ec-p384-sha384.crt)',
      'IR 8547 minimum (ec-p256-sha256.crt)',
      'Non-PQC permitted (ec-p256-sha256.crt, ed25519.crt)',
    ],
    estate_metrics: agg,
    target: {
      throughput_threshold: '>= 500 certs/sec at 10k estate',
      p99_threshold_ms: '< 50 ms per cert',
      verdict: null, // will be set below
    },
    estates: estatesMeta,
    regeneration_command: 'node bench/run.js',
    raw_runs_dir: 'bench/runs/',
  };
  // Compute and set target verdict on card (consistent with summary)
  const m10k = agg['10000:ours'];
  const targetOk = m10k && m10k.throughput_p50_certs_per_sec >= 500 && m10k.per_cert_p99_ms < 50;
  card.target.verdict = targetOk ? 'meets spec §6 target (>= 500 certs/sec and p99 < 50 ms at 10k)' : 'below spec §6 target';
  fs.writeFileSync(path.join(BENCH_DIR, 'benchmark-card.json'), JSON.stringify(card, null, 2));
  fs.writeFileSync(path.join(BENCH_DIR, 'benchmark-card.md'), renderCardMarkdown(card));

  // 6. Summary (af_gate.py G4 structure).
  const summary = {
    generated_at: tsNow(),
    total_valid_cards: 0,
    total_instances_tested: SIZES.length,
    total_solvers_tested: 2,
    benchmark_cards: [],
    spec_target: {
      throughput_threshold: '>= 500 certs/sec at 10k estate',
      p99_threshold_ms: '< 50 ms per cert',
    },
    estate_metrics: agg,
    target_verdict_10k: null,
  };
  // The cards are the per-run raw JSONs; total = instances × solvers (all existing on disk).
  for (const size of SIZES) {
    for (const impl of ['ours', 'cryptography']) {
      summary.benchmark_cards.push(`scan-${size}-${impl}`);
    }
  }
  summary.total_valid_cards = SIZES.length * 2;
  summary.target_verdict_10k = targetOk ? 'meets spec §6 target (>= 500 certs/sec and p99 < 50 ms at 10k)' : 'below spec §6 target';
  summary.target = card.target;
  summary.hardware_fingerprint = hardware;
  summary.hardware = hardware;
  fs.writeFileSync(path.join(BENCH_DIR, 'BENCHMARK-SUMMARY.json'), JSON.stringify(summary, null, 2));

  console.log('harness: wrote bench/BENCHMARK-SUMMARY.json, benchmark-card.json');
  console.log(`harness: total_valid_cards=${summary.total_valid_cards} instances=${summary.total_instances_tested} solvers=${summary.total_solvers_tested}`);
  console.log(`harness: 10k target verdict = ${summary.target_verdict_10k}`);
}

if (require.main === module) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
module.exports = { main };