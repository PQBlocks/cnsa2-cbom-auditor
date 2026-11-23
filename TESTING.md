# Testing Strategy

## Test Suite Overview

The package features a comprehensive test suite executed with Node.js built-in test runner (`node --test`).

```bash
# Run test suite
npm test
```

### Coverage Areas

1. **Parser Tests**:
   - `DER parser (bounded, no-indlen)`: Validates bounded TLV decoding, indefinite-length rejection, and memory ceilings.
   - `X.509 certificate parser`: Tests extraction of validity dates, subject/issuer DNs, signature OIDs, and public keys.
   - `SPKI public key parser`: Verifies SubjectPublicKeyInfo decoding across NIST PQC and classical algorithm sets.
   - `PKCS8 private key parser`: Verifies PKCS#8 key metadata extraction without secret leakage.
   - `PEM multi-block`: Verifies extraction of multiple blocks and bundle unwrapping.

2. **Classification & Policy**:
   - `Classification engine`: Evaluates assets against CNSA 2.0 requirements, verifying compliant, transition, and disallowed statuses.
   - `Mandate citation metadata`: Verifies citations of OMB M-26-15, NIST IR 8547, and NSA guidelines.

3. **CBOM Synthesis & Verification**:
   - `CBOM builder + schema validation`: Validates synthesized CBOM structures against CycloneDX 1.6 schemas.
   - `Verify subcommand`: Tests CLI and programmatic CBOM verification.
   - `Compare subcommand`: Tests differential comparison between baseline and post-migration CBOMs.

4. **Integration & Robustness**:
   - `Deterministic output`: Tests byte-level serialization stability.
   - `End-to-end integration`: End-to-end directory scan to CBOM synthesis and schema verification.
