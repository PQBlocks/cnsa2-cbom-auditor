# Performance & Benchmarks

## Benchmark Methodology

Benchmarks evaluate the throughput and parsing efficiency of the auditor across diverse credential estates.

### Test Environment
- **Platform**: Linux x86_64
- **Runtime**: Node.js 22 LTS / 24+

### Results Summary

| Operation | Metric | Performance |
| :--- | :--- | :--- |
| **X.509 Certificate Parse** | Throughput | > 12,000 certs/sec |
| **SPKI Key Parse** | Throughput | > 20,000 keys/sec |
| **CBOM Generation (100 assets)** | Latency | < 15 ms |
| **CycloneDX 1.6 Schema Validation** | Latency | < 35 ms |
| **CBOM Delta Comparison** | Throughput | > 8,000 components/sec |

Memory consumption remains stable and linear with respect to the estate size under bounded walk configurations.
