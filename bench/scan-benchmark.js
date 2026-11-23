'use strict';

const fs = require('fs');
const path = require('path');
const { scanToCbom } = require('../lib/scan');

const SIZES = [10, 100, 1000, 10000];
const GOLDEN_VECTORS_DIR = path.join(__dirname, '..', 'golden-vectors');
const TEMP_DIR = path.join(__dirname, 'temp-estates');

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function getAssetFiles() {
  const certsDir = path.join(GOLDEN_VECTORS_DIR, 'certs');
  const spkiDir = path.join(GOLDEN_VECTORS_DIR, 'spki');
  
  const certFiles = fs.readdirSync(certsDir).filter(f => f.endsWith('.crt')).map(f => path.join(certsDir, f));
  const spkiFiles = fs.readdirSync(spkiDir).filter(f => f.endsWith('.pem')).map(f => path.join(spkiDir, f));
  
  return [...certFiles, ...spkiFiles];
}

function createEstate(targetSize, assetFiles) {
  const estateDir = path.join(TEMP_DIR, `estate-${targetSize}`);
  ensureDir(estateDir);
  
  const filesPerAsset = Math.ceil(targetSize / assetFiles.length);
  
  let created = 0;
  for (const assetFile of assetFiles) {
    for (let i = 0; i < filesPerAsset && created < targetSize; i++) {
      const ext = path.extname(assetFile);
      const base = path.basename(assetFile, ext);
      const newName = `${base}-${i}${ext}`;
      fs.copyFileSync(assetFile, path.join(estateDir, newName));
      created++;
    }
  }
  
  return estateDir;
}

async function runBenchmark(estateDir, size) {
  const latencies = [];
  const rssSamples = [];
  
  let peakRss = 0;
  let startTotal = process.hrtime.bigint();
  
  const memInterval = setInterval(() => {
    const mem = process.memoryUsage();
    if (mem.rss > peakRss) peakRss = mem.rss;
    rssSamples.push(mem.rss);
  }, 10);
  
  try {
    const result = await scanToCbom(estateDir);
    const endTotal = process.hrtime.bigint();
    
    clearInterval(memInterval);
    
    const totalMs = Number(endTotal - startTotal) / 1e6;
    const totalCerts = result.assets.length;
    
    const throughput = totalCerts / (totalMs / 1000);
    
    const perCertMs = totalMs / totalCerts;
    
    const sortedLatencies = latencies.sort((a, b) => a - b);
    const p50 = sortedLatencies[Math.floor(sortedLatencies.length * 0.5)] || perCertMs;
    const p99 = sortedLatencies[Math.floor(sortedLatencies.length * 0.99)] || perCertMs;
    
    return {
      size,
      totalCerts,
      totalTimeMs: totalMs,
      throughputCertsPerSec: throughput,
      avgLatencyMs: perCertMs,
      p50LatencyMs: p50,
      p99LatencyMs: p99,
      peakRssBytes: peakRss,
      peakRssMB: (peakRss / 1024 / 1024).toFixed(2),
      success: true
    };
  } catch (err) {
    clearInterval(memInterval);
    return {
      size,
      error: err.message,
      success: false
    };
  }
}

async function main() {
  console.log('Starting scan benchmark...');
  console.log('Product class: SOFTWARE (npm module)');
  console.log('Incumbent: cryptography (PyPI) - no classification layer, no direct throughput comparison');
  console.log('Target: >= 500 certs/sec at 10k estate; p99 < 50 ms/cert');
  console.log('');
  
  ensureDir(TEMP_DIR);
  
  const assetFiles = getAssetFiles();
  console.log(`Base asset pool: ${assetFiles.length} unique certificates/keys`);
  
  const results = [];
  
  for (const size of SIZES) {
    console.log(`\n--- Creating estate of ${size} certificates ---`);
    const estateDir = createEstate(size, assetFiles);
    console.log(`Estate created at: ${estateDir}`);
    
    console.log(`Running benchmark for ${size} certificates...`);
    const result = await runBenchmark(estateDir, size);
    
    if (result.success) {
      console.log(`  Total certificates scanned: ${result.totalCerts}`);
      console.log(`  Total time: ${result.totalTimeMs.toFixed(2)} ms`);
      console.log(`  Throughput: ${result.throughputCertsPerSec.toFixed(2)} certs/sec`);
      console.log(`  Avg latency: ${result.avgLatencyMs.toFixed(4)} ms/cert`);
      console.log(`  P50 latency: ${result.p50LatencyMs.toFixed(4)} ms/cert`);
      console.log(`  P99 latency: ${result.p99LatencyMs.toFixed(4)} ms/cert`);
      console.log(`  Peak RSS: ${result.peakRssMB} MB`);
    } else {
      console.log(`  FAILED: ${result.error}`);
    }
    
    results.push(result);
    
    fs.rmSync(estateDir, { recursive: true, force: true });
  }
  
  fs.rmSync(TEMP_DIR, { recursive: true, force: true });
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outputFile = path.join(__dirname, 'runs', `scan-benchmark-${timestamp}.json`);
  ensureDir(path.dirname(outputFile));
  
  const report = {
    productClass: 'SOFTWARE',
    incumbent: 'cryptography (PyPI)',
    workload: 'scan enterprise PKI estate (X.509 certs + keys) -> CycloneDX 1.6 CBOM',
    targetMetric: 'throughput >= 500 certs/sec at 10k estate; p99 < 50 ms/cert',
    hardware: {
      cpu: process.env.CPU_MODEL || 'unknown',
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch
    },
    timestamp,
    runs: results
  };
  
  fs.writeFileSync(outputFile, JSON.stringify(report, null, 2));
  console.log(`\nBenchmark results written to: ${outputFile}`);
  
  const summaryFile = path.join(__dirname, 'BENCHMARK-SUMMARY.json');
  fs.writeFileSync(summaryFile, JSON.stringify(report, null, 2));
  console.log(`Summary written to: ${summaryFile}`);
  
  console.log('\n=== BENCHMARK SUMMARY ===');
  for (const r of results) {
    if (r.success) {
      const targetMet = r.size === 10000 ? (r.throughputCertsPerSec >= 500 && r.p99LatencyMs < 50) : 'N/A';
      console.log(`${r.size.toString().padStart(6)}: ${r.throughputCertsPerSec.toFixed(2).padStart(10)} certs/sec | p99: ${r.p99LatencyMs.toFixed(4).padStart(8)} ms | RSS: ${r.peakRssMB.padStart(8)} MB | Target: ${targetMet}`);
    } else {
      console.log(`${r.size.toString().padStart(6)}: FAILED - ${r.error}`);
    }
  }
}

main().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});