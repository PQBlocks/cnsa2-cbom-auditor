# Security Notes

## Threat Model and Security Guarantees

### 1. Scope
`@pqblocks/cnsa2-cbom-auditor` is an asset discovery, classification, and bill of materials generation tool. It inspects public certificates (X.509, SPKI), private key envelopes (PKCS#8), and JWK objects to determine compliance with CNSA 2.0 and NIST transition profiles.

### 2. Private Key Handling
- When scanning PKCS#8 private keys, the auditor only inspects the algorithm identifier, parameter OIDs, and key structure metadata.
- Raw private key bytes and cryptographic secrets are never written into generated CBOM output, log streams, or reports.

### 3. Parser Hardening
- **Bounded ASN.1/DER Parsing**: ASN.1 parsing enforces recursion depth limits (<= 128) and byte length maximums (<= 10 MB) to prevent denial-of-service via malformed or deeply nested TLV structures.
- **Strict BER/DER Validation**: Indefinite-length BER encoding is rejected. Only definite-length DER encoding is permitted.

### 4. Schema Conformance
All emitted CBOM structures are validated against the CycloneDX 1.6 JSON Schema before being returned to callers or written to disk.
