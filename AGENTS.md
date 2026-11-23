# AGENTS.md — AI Agent Guidance

## Project Summary
`@pqblocks/cnsa2-cbom-auditor` is an X.509 and key material auditor generating CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) compliant with NSA CNSA 2.0.

## Invariants
1. **Schema Validation**: All CBOM outputs must adhere to the CycloneDX 1.6 schema.
2. **Determinism**: Outputs must be sorted and canonically serializable.
3. **Bounded Processing**: File reads and ASN.1 depths must respect resource limits.
4. **Secret Protection**: Private key contents are never exported or logged.
