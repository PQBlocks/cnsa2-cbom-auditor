'use strict';
// S-13 — Findings emitter (machine-readable)
// Acceptance (spec/spec.md S-13): `lib/findings.js` exports
// `emitFindings(classifications) -> Finding[]`; every finding carries a rule id,
// a severity, an asset ref and a deadline; findings are separate from the CBOM
// (CycloneDX `additionalProperties: false`); P1–P12 each produce a finding with
// the correct rule id (brief/research-brief.md §5).
//
// Non-circularity: every expected rule id below is read from the brief's pitfall
// list, never derived from emitFindings' own output. Input records are built by
// the real parsers (lib/x509.js, lib/spki.js) + the real classifier
// (lib/classify.js), so the tests exercise the classification shape the product
// actually produces.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { readFileSync } = require('node:fs');

const { parseCert } = require('../lib/x509.js');
const { parseSpki } = require('../lib/spki.js');
const { classifyAsset } = require('../lib/classify.js');
const {
  emitFindings,
  validateFindings,
  InvalidFindingsError,
  FINDING_SCHEMA,
} = require('../lib/findings.js');

const LANE = path.dirname(__dirname);

function pemToDer(relPath) {
  const pem = readFileSync(path.join(LANE, 'golden-vectors', relPath), 'utf8');
  return Buffer.from(
    pem.split(/\r?\n/).filter((l) => l && !l.startsWith('-----')).join(''),
    'base64',
  );
}

function certRecord(relPath, extra = {}) {
  const cert = parseCert(pemToDer(relPath));
  const cls = classifyAsset(cert);
  return { ...cls, assetRef: relPath, notAfter: cert.notAfter, ...extra };
}

function keyRecord(relPath, extra = {}) {
  return {
    ...classifyAsset(parseSpki(pemToDer(relPath))),
    assetRef: relPath,
    ...extra,
  };
}

function byRule(findings, ruleId) {
  return findings.filter((f) => f.ruleId === ruleId);
}

const mlDsA87 = () => certRecord('certs/mldsa87.crt');
const rsa2048Key = () => keyRecord('spki/rsa2048-sha256.spki.pem');

// ---------------------------------------------------------------------------
// Output shape + input validation
// ---------------------------------------------------------------------------

test('every finding has exactly the contract fields and passes the findings schema', () => {
  const findings = emitFindings([rsa2048Key(), mlDsA87()]);
  assert.ok(Array.isArray(findings));
  assert.ok(findings.length > 0);
  const allowed = new Set(Object.keys(FINDING_SCHEMA.properties));
  for (const f of findings) {
    for (const key of Object.keys(f)) {
      assert.ok(allowed.has(key), `unexpected finding field "${key}"`);
    }
    assert.match(f.ruleId, /^P([1-9]|1[0-2])$/);
    assert.ok(['error', 'warning', 'info'].includes(f.severity));
    assert.ok(typeof f.assetRef === 'string' && f.assetRef.length > 0);
    assert.match(f.deadline, /^(\d{4}-\d{2}-\d{2}|immediate|N\/A)$/);
    assert.ok(typeof f.message === 'string' && f.message.length > 0);
  }
  assert.deepEqual(validateFindings(findings), findings);
});

test('findings are separate from the CBOM: no CBOM fields, schema closed', () => {
  assert.strictEqual(FINDING_SCHEMA.additionalProperties, false);
  const findings = emitFindings([rsa2048Key()]);
  for (const f of findings) {
    assert.ok(!Object.prototype.hasOwnProperty.call(f, 'cryptoProperties'));
    assert.ok(!Object.prototype.hasOwnProperty.call(f, 'bom-ref'));
    assert.ok(!Object.prototype.hasOwnProperty.call(f, 'type'));
  }
});

test('validateFindings rejects a finding with an extra field', () => {
  const findings = emitFindings([rsa2048Key()]);
  const polluted = { ...findings[0], cryptoProperties: {} };
  assert.throws(() => validateFindings([polluted]), InvalidFindingsError);
});

test('validateFindings rejects a non-array, a missing field, and a bad enum value', () => {
  assert.throws(() => validateFindings('P9'), InvalidFindingsError);
  const good = emitFindings([])[0];
  const { message, ...missingMessage } = good;
  assert.throws(() => validateFindings([missingMessage]), InvalidFindingsError);
  assert.throws(() => validateFindings([{ ...good, severity: 'fatal' }]), InvalidFindingsError);
  assert.throws(() => validateFindings([{ ...good, ruleId: 'P13' }]), InvalidFindingsError);
  assert.throws(() => validateFindings([{ ...good, deadline: 'next sprint' }]), InvalidFindingsError);
  assert.throws(() => validateFindings([{ ...good, assetRef: '' }]), InvalidFindingsError);
});

test('emitFindings rejects a non-array input loudly', () => {
  assert.throws(() => emitFindings(null), InvalidFindingsError);
  assert.throws(() => emitFindings({}), InvalidFindingsError);
});

test('emitFindings rejects a record that is not an object', () => {
  assert.throws(() => emitFindings([null]), InvalidFindingsError);
  assert.throws(() => emitFindings(['2.16.840.1.101.3.4.3.19']), InvalidFindingsError);
});

test('emitFindings rejects a record without a verdict', () => {
  assert.throws(
    () => emitFindings([{ oid: '2.16.840.1.101.3.4.3.19', assetRef: 'x' }]),
    InvalidFindingsError,
  );
});

test('emitFindings rejects a verdict outside the classification enum', () => {
  assert.throws(
    () => emitFindings([{ verdict: 'looks-fine', oid: '2.16.840.1.101.3.4.3.19' }]),
    InvalidFindingsError,
  );
});

test('emitFindings rejects a record with neither oid nor assetRef (no asset ref possible)', () => {
  assert.throws(() => emitFindings([{ verdict: 'compliant' }]), InvalidFindingsError);
});

// ---------------------------------------------------------------------------
// One test per pitfall rule P1–P12 (brief §5)
// ---------------------------------------------------------------------------

test('P1: a verdict claimed for an unregistered OID is an error (never length-derived)', () => {
  const forged = {
    ...mlDsA87(),
    oid: '1.2.3.4.5.6.7.8.9',
    verdict: 'compliant',
  };
  const findings = emitFindings([forged]);
  const p1 = byRule(findings, 'P1');
  assert.strictEqual(p1.length, 1);
  assert.strictEqual(p1[0].severity, 'error');
  assert.ok(p1[0].message.includes('1.2.3.4.5.6.7.8.9'));
});

test('P2: an unknown OID is an error and carries the raw OID', () => {
  const unknown = classifyAsset({ oid: '1.2.3.4.5.6.7.8.9', keyBytes: null });
  assert.strictEqual(unknown.verdict, 'unknown');
  assert.strictEqual(unknown.nistQuantumSecurityLevel, undefined);
  const findings = emitFindings([{ ...unknown, assetRef: 'keys/unknown.pem' }]);
  const p2 = byRule(findings, 'P2');
  assert.strictEqual(p2.length, 1);
  assert.strictEqual(p2[0].severity, 'error');
  assert.strictEqual(p2[0].assetRef, 'keys/unknown.pem');
  assert.ok(p2[0].message.includes('unknown'));
  assert.ok(p2[0].message.includes('1.2.3.4.5.6.7.8.9'));
});

test('P3: signature and subject-key verdicts differ -> warning naming both', () => {
  const record = { ...mlDsA87(), keyClassification: rsa2048Key() };
  const assert0 = record.verdict; // ML-DSA-87 signature: compliant
  const keyVerdict = record.keyClassification.verdict; // RSA-2048 key: deprecated
  assert.notStrictEqual(assert0, keyVerdict);
  const p3 = byRule(emitFindings([record]), 'P3');
  assert.strictEqual(p3.length, 1);
  assert.strictEqual(p3[0].severity, 'warning');
  assert.ok(p3[0].message.includes('ML-DSA-87'));
  assert.ok(p3[0].message.includes('RSA-2048'));
});

test('P3: identical signature and key verdicts emit no P3', () => {
  const record = { ...certRecord('certs/mldsa87.crt'), keyClassification: keyRecord('spki/mldsa87.spki.pem') };
  assert.strictEqual(byRule(emitFindings([record]), 'P3').length, 0);
});

test('P4: a PQ algorithm outside CNSA 2.0 is a warning with the 2033 adoption deadline', () => {
  const p4 = byRule(emitFindings([keyRecord('spki/slhdsa-shake-256f.spki.pem')]), 'P4');
  assert.strictEqual(p4.length, 1);
  assert.strictEqual(p4[0].severity, 'warning');
  assert.strictEqual(p4[0].deadline, '2033-12-31');
  assert.ok(p4[0].message.includes('CNSA'));
  assert.ok(p4[0].message.includes('SLH-DSA'));
});

test('P5: RSA-2048 emits two findings, one per disagreeing mandate', () => {
  const p5 = byRule(emitFindings([rsa2048Key()]), 'P5');
  assert.strictEqual(p5.length, 2, 'IR 8547 and CNSA 1.0 findings must not be collapsed');
  const ir = p5.find((f) => f.mandate === 'NIST IR 8547');
  const cnsa = p5.find((f) => f.mandate === 'CNSA 1.0');
  assert.ok(ir, 'missing IR 8547 finding');
  assert.strictEqual(ir.severity, 'warning');
  assert.strictEqual(ir.deadline, '2030-12-31');
  assert.ok(cnsa, 'missing CNSA 1.0 finding');
  assert.strictEqual(cnsa.severity, 'error');
  assert.strictEqual(cnsa.deadline, 'immediate');
  assert.ok(cnsa.message.includes('3072'));
});

test('P5: RSA-3072 meets the CNSA 1.0 floor and yields only the IR 8547 finding', () => {
  const p5 = byRule(emitFindings([keyRecord('spki/rsa3072-sha384.spki.pem')]), 'P5');
  assert.strictEqual(p5.length, 1);
  assert.strictEqual(p5[0].mandate, 'NIST IR 8547');
});

test('P5: EC P-256 is below the CNSA 1.0 P-384 floor -> two findings', () => {
  const p5 = byRule(emitFindings([keyRecord('spki/ec-p256-sha256.spki.pem')]), 'P5');
  assert.strictEqual(p5.length, 2);
  assert.ok(p5.some((f) => f.mandate === 'CNSA 1.0' && f.message.includes('P-384')));
});

test('P6: a PQ leaf under a classical issuer is a warning at the issuer deadline', () => {
  const record = { ...mlDsA87(), issuerClassification: rsa2048Key() };
  const p6 = byRule(emitFindings([record]), 'P6');
  assert.strictEqual(p6.length, 1);
  assert.strictEqual(p6[0].severity, 'warning');
  assert.strictEqual(p6[0].deadline, '2030-12-31');
  assert.ok(p6[0].message.includes('issuer'));
});

test('P6: a compliant issuer emits no P6', () => {
  const record = {
    ...mlDsA87(),
    issuerClassification: keyRecord('spki/mldsa87.spki.pem'),
  };
  assert.strictEqual(byRule(emitFindings([record]), 'P6').length, 0);
});

test('P7: a deprecated certificate expiring after the 2035 disallowance is an error', () => {
  // Golden rsa3072 cert: notAfter 2036, i.e. after the IR 8547 disallowance.
  const record = certRecord('certs/rsa3072-sha384.crt');
  assert.strictEqual(record.verdict, 'deprecated');
  assert.ok(record.notAfter.getUTCFullYear() > 2035);
  const p7 = byRule(emitFindings([record]), 'P7');
  assert.strictEqual(p7.length, 1);
  assert.strictEqual(p7[0].severity, 'error');
  assert.strictEqual(p7[0].deadline, '2035-12-31');
  assert.ok(p7[0].message.includes('2035'));
});

test('P7: expiry exactly at the disallowance instant is not after it (no P7)', () => {
  const record = {
    ...certRecord('certs/rsa3072-sha384.crt'),
    notAfter: new Date('2035-12-31T23:59:59Z'),
  };
  assert.strictEqual(byRule(emitFindings([record]), 'P7').length, 0);
});

test('P7: a compliant PQ certificate is not flagged with the IR 8547 disallowance', () => {
  // ML-DSA-87 has no IR 8547 disallowance date; reporting one would be false.
  const record = certRecord('certs/mldsa87.crt');
  assert.strictEqual(record.verdict, 'compliant');
  assert.strictEqual(byRule(emitFindings([record]), 'P7').length, 0);
});

test('P8: an ML-KEM key with digitalSignature keyUsage is an error (KEM cannot sign)', () => {
  const record = {
    ...keyRecord('spki/mlkem1024.spki.pem'),
    keyUsage: ['digitalSignature'],
  };
  const p8 = byRule(emitFindings([record]), 'P8');
  assert.strictEqual(p8.length, 1);
  assert.strictEqual(p8[0].severity, 'error');
  assert.strictEqual(p8[0].deadline, 'immediate');
  assert.ok(p8[0].message.includes('KEM'));
});

test('P8: the RFC 9935 keyEncipherment usage emits no P8', () => {
  const record = {
    ...keyRecord('spki/mlkem1024.spki.pem'),
    keyUsage: ['keyEncipherment'],
  };
  assert.strictEqual(byRule(emitFindings([record]), 'P8').length, 0);
});

test('P9: the scope statement is always present, even for an empty scan', () => {
  const findings = emitFindings([]);
  const p9 = byRule(findings, 'P9');
  assert.strictEqual(p9.length, 1);
  assert.strictEqual(p9[0].severity, 'info');
  assert.strictEqual(p9[0].assetRef, 'scan');
  assert.strictEqual(p9[0].deadline, 'N/A');
  assert.ok(/hybrid|scope/i.test(p9[0].message));
});

test('P10: a DER parser limit violation is an error, never silently accepted', () => {
  const indefinite = { ...mlDsA87(), der: { indefiniteLength: true } };
  const tooDeep = { ...mlDsA87(), der: { depth: 129 } };
  assert.strictEqual(byRule(emitFindings([indefinite]), 'P10').length, 1);
  const p10 = byRule(emitFindings([tooDeep]), 'P10');
  assert.strictEqual(p10.length, 1);
  assert.strictEqual(p10[0].severity, 'error');
  assert.ok(p10[0].message.includes('128'));
});

test('P10: a record within the DER bounds emits no P10', () => {
  const ok = { ...mlDsA87(), der: { depth: 128, indefiniteLength: false } };
  assert.strictEqual(byRule(emitFindings([ok]), 'P10').length, 0);
});

test('P11: key material in a record is an error and is never echoed into output', () => {
  const secret = Buffer.from('this-is-a-private-key-do-not-print', 'utf8');
  const record = { ...mlDsA87(), keyBytes: secret };
  const findings = emitFindings([record]);
  const p11 = byRule(findings, 'P11');
  assert.strictEqual(p11.length, 1);
  assert.strictEqual(p11[0].severity, 'error');
  assert.strictEqual(p11[0].deadline, 'immediate');
  const serialised = JSON.stringify(findings);
  assert.ok(!serialised.includes(secret.toString('utf8')));
  assert.ok(!serialised.includes(secret.toString('base64')));
  assert.ok(!serialised.includes(secret.toString('hex')));
});

test('P12: a non-UTC timestamp string is an error (parse from DER, not local time)', () => {
  const naive = { ...mlDsA87(), notAfter: '2036-12-31 23:59:59' };
  const p12 = byRule(emitFindings([naive]), 'P12');
  assert.strictEqual(p12.length, 1);
  assert.strictEqual(p12[0].severity, 'error');
  assert.ok(p12[0].message.includes('UTC'));
  // A naive timestamp must not also be silently parsed into a P7 verdict.
  assert.strictEqual(byRule(emitFindings([naive]), 'P7').length, 0);
});

test('P12: a DER Date and an explicit-offset timestamp are absolute (no P12)', () => {
  assert.strictEqual(
    byRule(emitFindings([{ ...mlDsA87(), notAfter: new Date('2036-12-31T23:59:59Z') }]), 'P12').length,
    0,
  );
  assert.strictEqual(
    byRule(emitFindings([{ ...mlDsA87(), notAfter: '2036-12-31T23:59:59+05:30' }]), 'P12').length,
    0,
  );
});

// ---------------------------------------------------------------------------
// Verdict coverage + determinism
// ---------------------------------------------------------------------------

test('a compliant ML-DSA-87 certificate produces only the informational scope finding', () => {
  const findings = emitFindings([mlDsA87()]);
  assert.deepEqual(
    findings.map((f) => f.ruleId),
    ['P9'],
    'compliant asset must not produce error/warning findings',
  );
});

test('a disallowed PQ key produces P4, not the classical-mandate P5', () => {
  const findings = emitFindings([keyRecord('spki/mldsa65.spki.pem')]);
  assert.strictEqual(byRule(findings, 'P4').length, 1);
  assert.strictEqual(byRule(findings, 'P5').length, 0);
});

test('emitFindings is deterministic: same input yields deep-equal findings', () => {
  const input = () => [rsa2048Key(), mlDsA87(), keyRecord('spki/mlkem1024.spki.pem', { keyUsage: ['digitalSignature'] })];
  assert.deepEqual(emitFindings(input()), emitFindings(input()));
});

test('end-to-end: the golden RSA-2048 certificate yields both mandates and the expiry finding', () => {
  // Real DER -> parseCert -> classifyAsset -> emitFindings (no synthetic record).
  const record = certRecord('certs/rsa2048-sha256.crt');
  const ids = emitFindings([record]).map((f) => f.ruleId);
  assert.deepEqual(ids, ['P5', 'P5', 'P7', 'P9']);
  const mandates = emitFindings([record]).filter((f) => f.ruleId === 'P5').map((f) => f.mandate);
  assert.deepEqual(mandates, ['NIST IR 8547', 'CNSA 1.0']);
});
