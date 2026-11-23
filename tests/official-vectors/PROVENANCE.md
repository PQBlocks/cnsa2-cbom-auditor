# Official ACVP vectors — provenance (R1; R17 denominator preservation)

Set: acvp `ML-DSA-sigVer-FIPS204` (vsId 42; FIPS 204; sigVer AFT).
Source: NIST ACVP server (gen-val), cached at `~/.cache/official ACVP vectors/ACVP-Server/gen-val/json-files/ML-DSA-sigVer-FIPS204/`
(retrieved there by the factory's vector fetch, 2026-10-07). Files vendored
byte-identical into this directory on 2026-11-15; hashes below.

| File | sha256 | Role |
|---|---|---|
| prompt.json | `e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e` | test groups + vectors |
| expectedResults.json | `e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6` | expected per-case pass/fail |
| validation.json | `2433c4bada43c5257e7424490cdccacf2cb0a08dc302cadd9d9447ecf79c5a89` | ACVP registration/validation record |
| registration.json | `55878cee2c7a8cf275f4138231f1b5f98880ff81a99face609207415053fb859` | ACVP server registration |
| internalProjection.json | `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437` | ACVP test groups with expected results inline (the set's hash-indexed official file) |

This lane's spec §4 deliberately does NOT claim ACVP conformance
(estate-level verification is against the incumbent openssl shell loop).
These vectors are vendored only to measure the delegated engine
(node:crypto, OpenSSL 3.6.5) against the published corpus — no ACVP
certificate, no validation-claim, is made or implied.

Observed 2026-11-15 (see tests/official-vectors.test.js), for the 60
ML-DSA-87 cases (of 180 in the set):
- tgId 5 (external, pure, context-bearing): 12/15 match ACVP; 3 expected-valid
  vectors (tcId 63, 67, 70; context 58/93/255 bytes) rejected by node:crypto —
  node has no context parameter for ML-DSA verification.
- tgId 6 (external, preHash SHA3-512): 15/15 not expressible via node:crypto
  (no API to bind a different pre-hash algorithm to ML-DSA verification).
- tgId 11 (internal, mu given): 15/15 not expressible without implementing the
  FIPS 204 μ derivation — out of hand (never hand-rolled).
- tgId 12 (internal, pure): 12/15 match; 3 expected-valid vectors
  (tcId 168, 178, 180) rejected by node:crypto.
- Total expressed 30/60; match 24/30; mismatch 6 (tcIds 63, 67, 70, 168, 178, 180);
  unexpressible 30 (tgIds 6, 11). Fix belongs to node/OpenSSL, not to this lane.
