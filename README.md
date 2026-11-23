# @pqblocks/cnsa2-cbom-auditor

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Stable-059669.svg)](https://pqblocks.github.io)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6%20CBOM-blue.svg)](https://cyclonedx.org)
[![NIST FIPS](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-purple.svg)](https://csrc.nist.gov)

> CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) generator, validator, and delta comparator enforcing NSA CNSA 2.0 and NIST Post-Quantum Cryptography transition timelines.

---

## Overview

`@pqblocks/cnsa2-cbom-auditor` scans filesystem trees, directories, and credential stores for X.509 certificates, SubjectPublicKeyInfo (SPKI) keys, PKCS#8 private keys, and JSON Web Keys (JWK). It analyzes each cryptographic asset against the NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) mandates, NIST IR 8547 guidelines, and NIST FIPS 203/204/205 standards.

The auditor generates strictly schema-validated CycloneDX 1.6 Cryptographic Bill of Materials (CBOM), checks policy compliance, verifies existing CBOM files against the official JSON schema, and provides automated delta comparison between baseline and target audits.

### Key Features

* **Comprehensive Asset Detection**: Scans and parses X.509 leaf/intermediate/root certificates, SPKI public keys, PKCS#8 private keys, and JWK/JWKS structures in PEM, DER, and JSON formats.
* **CNSA 2.0 Policy Classification**:
  * **Compliant**: State-of-the-art post-quantum algorithms authorized under CNSA 2.0 (e.g. ML-KEM-1024, ML-DSA-87, SLH-DSA-SHAKE-256s).
  * **Transition**: Interim transitional configurations (e.g. RSA-3072, ECDSA P-384).
  * **Disallowed / Deprecated**: Classical algorithms scheduled for deprecation by 2030 (RSA-2048, SHA-1, P-256) or non-compliant PQC parameter sets.
* **Official CycloneDX 1.6 CBOM Export**: Emits standard-compliant CycloneDX 1.6 CBOM records with cryptographic properties, asset classifications, and machine-readable findings.
* **CBOM Verification Engine**: Validates arbitrary CBOM files against the official CycloneDX 1.6 JSON Schema via AJV and checks adherence to quantum-readiness rules.
* **Migration Delta Comparator**: Diffs two CBOM instances to verify migration progress, identifying newly introduced assets, retired legacy algorithms, and policy status changes.
* **Strict Determinism**: Produces byte-for-byte identical CBOM outputs across repeated runs on identical inputs.

---

## Installation

Install via npm:

```bash
npm install @pqblocks/cnsa2-cbom-auditor
```

Or install globally to use the CLI directly:

```bash
npm install -g @pqblocks/cnsa2-cbom-auditor
```

---

## CLI Usage

The package exposes the command-line utility `cnsa2-cbom-audit` (aliased as `cnsa2-cbom` and `pqblocks-cnsa-evidence`).

```bash
cnsa2-cbom-audit <command> [options]
```

### 1. `scan` — Audit Directories and Generate CBOM

Scans a directory or file and outputs a CycloneDX 1.6 CBOM:

```bash
# Scan a directory and print human-readable table summary
cnsa2-cbom-audit scan --target /etc/ssl/certs --format table

# Scan and export CycloneDX 1.6 CBOM to a JSON file
cnsa2-cbom-audit scan --target ./certs --format json --out ./cbom.json

# Fail with non-zero exit code if disallowed algorithms are found
cnsa2-cbom-audit scan --target ./certs --fail-on disallowed
```

### 2. `verify` — Validate CBOM Structure and Compliance

Validates an existing CBOM file against the official CycloneDX 1.6 schema:

```bash
# Verify schema validity
cnsa2-cbom-audit verify --cbom ./cbom.json

# Fail if any non-compliant findings exist in the CBOM
cnsa2-cbom-audit verify --cbom ./cbom.json --fail-on any
```

### 3. `compare` — Compare Before & After Migration CBOMs

Compares a baseline CBOM against a post-migration CBOM to prove progress:

```bash
# Output migration difference in table format
cnsa2-cbom-audit compare --before ./baseline-cbom.json --after ./current-cbom.json

# Output delta report in JSON format
cnsa2-cbom-audit compare --before ./baseline.json --after ./current.json --format json --out delta.json
```

---

## Exit Codes

The CLI follows standard POSIX exit status conventions:

| Exit Code | Meaning | Description |
| :---: | :--- | :--- |
| **`0`** | **Success** | Scan, verification, or comparison completed cleanly with no policy violations. |
| **`1`** | **Internal Error** | File not found, I/O failure, or unrecoverable execution error. |
| **`3`** | **Policy Findings** | Audit completed successfully, but assets matching the `--fail-on` filter were detected. |
| **`4`** | **Usage Error** | Missing required parameters, unknown command, or invalid argument syntax. |

---

## Programmatic API

The package provides a clean, synchronous and asynchronous programmatic JavaScript/TypeScript API:

```javascript
const {
  scan,
  scanToCbom,
  scanTarget,
  generateCbom,
  verifyCbom,
  compareCboms,
  classify
} = require('@pqblocks/cnsa2-cbom-auditor');

// 1. Scan a directory of certificates
async function runAudit() {
  const result = await scanToCbom('./golden-vectors', {
    maxFiles: 1000,
    failOn: 'disallowed'
  });

  console.log('Total Assets Found:', result.summary.total);
  console.log('Compliant Assets:', result.summary.compliant);
  console.log('Disallowed Assets:', result.summary.disallowed);

  // 2. Access the CycloneDX 1.6 BOM object
  const bom = result.bom;
  console.log('CycloneDX BOM Format:', bom.bomFormat); // "CycloneDX"
  console.log('Spec Version:', bom.specVersion);       // "1.6"

  // 3. Verify the generated CBOM
  const verification = verifyCbom(bom);
  console.log('CBOM Valid against Schema:', verification.valid);

  // 4. Classify an individual asset
  const sampleAsset = result.assets[0];
  const verdict = classify(sampleAsset);
  console.log(`Asset ${sampleAsset.file}: status=${verdict.verdict}, reason=${verdict.reason}`);
}

runAudit().catch(console.error);
```

### API Reference Table

| Function | Signature | Description |
| :--- | :--- | :--- |
| `scan(path, opts)` | `(string, object?) => Promise<ScanReport>` | High-level estate scan returning findings and summary counters. |
| `scanToCbom(path, opts)` | `(string, object?) => Promise<{ bom, assets, summary }>` | Scans filesystem and directly synthesizes a schema-valid CycloneDX 1.6 CBOM. |
| `scanTarget(path, opts)` | `(string, object?) => Promise<Asset[]>` | Core scanner returning normalized cryptographic asset descriptors. |
| `generateCbom(assets, opts)` | `(Asset[], object?) => object` | Constructs CycloneDX 1.6 CBOM document from inspected asset list. |
| `verifyCbom(pathOrObject, opts)` | `(string\|object, object?) => { valid, bom, findings }` | Validates arbitrary CBOM against CycloneDX 1.6 JSON Schema. |
| `compareCboms(before, after)` | `(object, object) => DeltaReport` | Calculates additions, deletions, and classification transitions between CBOMs. |
| `classify(asset)` | `(Asset) => Classification` | Evaluates an asset's OID and key parameters against CNSA 2.0 mandates. |

---

## Standards Conformance

* **NSA CNSA 2.0**: Enforces Algorithm Suite 2.0 requirements for national security systems.
* **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
* **NIST FIPS 204**: Module-Lattice-Based Digital Signature Algorithm (ML-DSA).
* **NIST FIPS 205**: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA).
* **NIST IR 8547**: Transition to Post-Quantum Cryptography standards and deadlines.
* **CycloneDX 1.6**: Official Cryptographic Bill of Materials (CBOM) standard specification.

---

## Authors & Contributors

* **Govind Dubey** ([@MrGovindDubey](https://github.com/MrGovindDubey)) — *Core Architecture & Implementation* (`govinddubeycse@gmail.com`)
* **PQBlocks Community** — *Security Reviews and Standards Alignment*

---

## Security & Vulnerability Reporting

Please report security issues or vulnerabilities via:
1. **GitHub Security Advisory**: [Report a Vulnerability](https://github.com/PQBlocks/cnsa2-cbom-auditor/security/advisories/new)
2. **Author Direct Email**: Govind Dubey (`govinddubeycse@gmail.com`)
3. **GitHub Issues**: Non-sensitive defect tracking at [Issues](https://github.com/PQBlocks/cnsa2-cbom-auditor/issues)

---

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.
