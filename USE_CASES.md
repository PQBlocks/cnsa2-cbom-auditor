# Use Cases

## Practical Deployment Scenarios

### 1. CI/CD Cryptography Regression Gate
Integrate into build pipelines to block codebases from introducing deprecated classical cryptographic algorithms or non-compliant key sizes:
```bash
cnsa2-cbom-audit scan --target ./deploy/certs --fail-on disallowed
```

### 2. Regulatory Compliance & CBOM Reporting
Generate machine-readable CycloneDX 1.6 Cryptographic Bill of Materials for compliance audits and federal supply-chain reporting (OMB M-26-15):
```bash
cnsa2-cbom-audit scan --target ./pki --format json --out cbom.json
```

### 3. Post-Quantum Migration Tracking
Track progress during multi-year PQC transition programs by comparing periodic baseline snapshots:
```bash
cnsa2-cbom-audit compare --before 2025-baseline.json --after 2026-audit.json
```
