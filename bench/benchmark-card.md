# pqblocks-cnsa-evidence — CNSA 2.0 PKI auditor scan workload

Generated: 2026-11-19T19:06:19.435Z  
Product class: SOFTWARE  
Workload: scan estate: 10 / 100 / 1000 / 10000 X.509 certificates (spec §6)  
Regeneration command: `node bench/run.js`  
Raw runs: bench/runs/

## Provenance

- Ours: pqblocks-cnsa-evidence src/scan.js scanTarget (npm, package.json version 0.0.0)  
- Baseline: cryptography 50.0.2 (PyPI, Python 3.14.9) — reference only, lacks classification layer  
- Runtime: node v26.13.0  
- Hardware: Intel(R) Core(TM) i5-10300H CPU @ 2.50GHz, 8 threads, governor cpufreq-3199.981MHz, 23.3 GB RAM  
- CI method: bootstrap percentile (B=10000, level=95%)  
- Tuning budget: none (deterministic scan on both sides; no parameter search)

## Results (median [p50] / p99, wall-clock ms and certs/sec)

| estate | side | runs | wall p50 (95% CI) | wall p99 (95% CI) | per-cert p99 ms | throughput p50 certs/s | success |
|---:|---|---:|---|---|---|---:|---:|
| 10 | ours | 100 | 0.616 [0.579, 0.6805] | 1.485 [0.4614200000000018, 1.3400899999999965] | 0.149 | 16236.9 | 1 |
| 10 | cryptography | 30 | 78.574 [73.69149999999999, 90.117] | 139.671 [67.53075, 129.741] | 13.967 | 127.3 | 1 |
| 100 | ours | 50 | 9.909 [9.329, 10.72] | 21.334 [5.997189999999998, 16.259259999999987] | 0.213 | 10091.8 | 1 |
| 100 | cryptography | 20 | 98.956 [91.199, 108.21549999999999] | 133.177 [83.33, 128.30758999999998] | 1.332 | 1010.5 | 1 |
| 1000 | ours | 20 | 71.474 [68.108, 93.3095] | 111.267 [61.46895000000001, 107.772] | 0.111 | 13991.3 | 1 |
| 1000 | cryptography | 10 | 204.803 [178.305, 215.003] | 218.965 [170.41198, 218.72854] | 0.219 | 4882.8 | 1 |
| 10000 | ours | 10 | 909.771 [751.707, 1010.118] | 1215.496 [713.22401, 1208.86291] | 0.122 | 10991.9 | 1 |
| 10000 | cryptography | 10 | 1431.598 [1266.488, 2080.027] | 2409.349 [1207.89765, 2396.48496] | 0.241 | 6994.8 | 1 |

## Target

- Throughput threshold: >= 500 certs/sec at 10k estate  
- p99 threshold: < 50 ms per cert  
- Verdict: meets spec §6 target (>= 500 certs/sec and p99 < 50 ms at 10k)

## Notes

- Baseline `cryptography` is a parse-speed reference only: it has no classification layer, so throughput is NOT a like-for-like product comparison (spec §6). The product number is judged against the spec §6 target.
- Both sides parse the identical deterministic estate (same golden cert files tiled round-robin); success = all estate files parsed.
- Warm-up runs excluded (documented, not in statistics). Baseline wall-clock includes Python interpreter startup per run, disclosed on the card.