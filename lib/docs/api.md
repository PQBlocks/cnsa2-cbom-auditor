# API Documentation — @pqblocks/cnsa2-cbom-auditor

## Core Modules

### `scan`
Scan files and directories for X.509, PKCS#8, SPKI, and JWK cryptographic materials.

- `scan(targetPath: string, options?: ScanOptions): Promise<ScanResult>`
- `scanToCbom(targetPath: string, options?: ScanOptions): Promise<{ bom: object, assets: Asset[], summary: object }>`
- `scanTarget(targetPath: string, options?: ScanOptions): Promise<Asset[]>`

### `cbom`
Generate compliant CycloneDX 1.6 Cryptographic Bill of Materials.

- `generateCbom(assets: Asset[], options?: CbomOptions): object`
- Generates a valid CycloneDX 1.6 BOM adhering to the official JSON schema.

### `verify`
Verify CBOM structure and validate compliance against CNSA 2.0.

- `verifyCbom(cbomPath: string): { schemaOk: boolean, validated: boolean, errors?: string[] }`
- Validates the CBOM against CycloneDX 1.6 schema and checks for schema conformance.

### `classify`
Classify algorithms and key parameters according to CNSA 2.0 and NIST transition profiles.

- `classify(asset: Asset): ClassificationResult`
- Returns verdict: `'compliant'`, `'transition'`, or `'disallowed'`.

### `compare`
Compare two CBOMs and output structural and policy deltas.

- `compareCboms(beforeCbom: object, afterCbom: object): DeltaReport`
