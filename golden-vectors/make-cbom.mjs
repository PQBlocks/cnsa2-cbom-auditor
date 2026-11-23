#!/usr/bin/env node
// make-cbom.mjs — turn expected-classification.json into a minimal CycloneDX 1.6
// CBOM.  This is a *reference shape* for the architect, not product code: it is
// derived only from the independent oracle output and the schema fields named in
// the brief (§3.4).  Validate with:
//   /home/hunt/.hermes/factory-env/bin/python -c "import json,jsonschema; \
//     jsonschema.validate(json.load(open('golden-vectors/expected/sample-cbom.json')), \
//     json.load(open('brief/references/cyclonedx-bom-1.6.schema.json')))"
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';

const dir = path.dirname(new URL(import.meta.url).pathname);
const exp = JSON.parse(readFileSync(path.join(dir, 'expected', 'expected-classification.json'), 'utf8'));

const bomRef = (f) => 'crypto-asset:' + createHash('sha256').update(f).digest('hex').slice(0, 16);

// Signature-algorithm name (as OpenSSL prints it) -> dotted OID.  Values from
// RFC 8017 (PKCS#1), RFC 5758/5480 (ECDSA), RFC 8410 (Ed25519), and RFC 9881 /
// RFC 9909 for the PQ entries — the same OIDs the brief's §1.6 tables list.
const SIG_OID = {
  sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
  sha384WithRSAEncryption: '1.2.840.113549.1.1.12',
  sha512WithRSAEncryption: '1.2.840.113549.1.1.13',
  'ecdsa-with-SHA256': '1.2.840.10045.4.3.2',
  'ecdsa-with-SHA384': '1.2.840.10045.4.3.3',
  ED25519: '1.3.101.112',
  'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
  'ML-DSA-65': '2.16.840.1.101.3.4.3.18',
  'ML-DSA-87': '2.16.840.1.101.3.4.3.19',
  'SLH-DSA-SHA2-128s': '2.16.840.1.101.3.4.3.20',
  'SLH-DSA-SHAKE-256f': '2.16.840.1.101.3.4.3.31',
};

const components = [];
for (const c of exp.certificates) {
  const ref = bomRef(c.file);
  const sigOid = SIG_OID[c.signatureAlgorithm];
  if (!sigOid) throw new Error(`no OID mapping for signature algorithm "${c.signatureAlgorithm}"`);
  components.push({
    type: 'cryptographic-asset',
    'bom-ref': ref,
    name: path.basename(c.file),
    cryptoProperties: {
      assetType: 'certificate',
      oid: sigOid,
      certificateProperties: {
        subjectName: c.subjectDn,
        issuerName: c.subjectDn, // self-signed golden vectors
        notValidBefore: new Date(Date.parse(c.notBefore)).toISOString(),
        notValidAfter: new Date(Date.parse(c.notAfter)).toISOString(),
        certificateFormat: 'X.509',
        signatureAlgorithmRef: bomRef(c.file + '#sig'),
        subjectPublicKeyRef: bomRef(c.file + '#key'),
      },
      algorithmProperties: {
        primitive: c.publicKey.primitive,
        parameterSetIdentifier: c.publicKey.paramSet || c.publicKey.family,
        classicalSecurityLevel: c.publicKey.classicalBits || 0,
        nistQuantumSecurityLevel: c.publicKey.nistQuantumSecurityLevel,
      },
    },
  });
}

const bom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.6',
  serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
  version: 1,
  metadata: {
    timestamp: exp.generatedUtc,
    tools: { components: [{ type: 'application', name: 'pqblocks-cnsa-evidence', version: '0.1.0' }] },
    properties: [
      { name: 'cnsa2:mandate', value: 'NSA CNSA 2.0 (U/OO/194427-22, SEP 2022 v1.0)' },
      { name: 'nist:transition', value: 'NIST IR 8547 (October 2026) Tables 2 and 4' },
      { name: 'classification:oracle', value: exp.oracle },
    ],
  },
  components,
};

writeFileSync(path.join(dir, 'expected', 'sample-cbom.json'), JSON.stringify(bom, null, 2) + '\n');
console.log(`wrote sample-cbom.json with ${components.length} cryptographic-asset components`);
