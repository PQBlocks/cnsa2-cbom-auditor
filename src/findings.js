// lib/findings.js — S-13: Findings emitter (machine-readable).
//
// emitFindings(classifications) -> Finding[]
//
// PURPOSE
//   Turn per-asset classifications (lib/classify.js, S-06) into a machine-readable
//   findings array that CI can gate on. A Finding is deliberately *not* a CBOM
//   component: CycloneDX 1.6 runs with `additionalProperties: false`, so findings
//   are emitted as a separate array with their own closed schema (FINDING_SCHEMA).
//
// FINDING
//   { ruleId, severity, assetRef, deadline, message, mandate? }
//     ruleId   P1..P12 — the pitfall each rule enforces (brief §5)
//     severity 'error' | 'warning' | 'info'
//     assetRef file path / DN / OID of the asset the finding is about
//     deadline ISO date (YYYY-MM-DD), 'immediate', or 'N/A'
//     message  one actionable sentence, no key material, no unsupported claims
//     mandate  optional source of the rule ('NIST IR 8547', 'CNSA 1.0', ...)
//
// INPUT
//   An array of classification records. A record is a Classification as returned
//   by classifyAsset(), optionally joined with the context a rule needs. None of
//   the optional fields is invented here: each one is a value the lane's parsers
//   already produce, and a rule stays silent when its context is absent rather
//   than guessing.
//
//     oid, verdict, pqSecure, cnsa20Compliant, family, parameterSetIdentifier,
//     deadline, nistQuantumSecurityLevel      from lib/classify.js (S-06)
//     assetRef      string   file path, DN, or another stable asset reference
//     notAfter      Date|string  from lib/x509.js parseCert (DER-decoded UTC)
//     keyUsage      string[] from the certificate's KeyUsage extension
//     keyClassification  Classification of subjectPublicKeyInfo (P3 dual verdict)
//     issuerClassification Classification of the issuer certificate (P6 chain)
//     der           { depth?:number, indefiniteLength?:boolean } parser telemetry
//
// RULES (each rule id is exercised by a dedicated test in
// tests/Findings emitter (machine-readable).test.js)
//   P1  a known verdict must be backed by an OID-registry entry; a verdict for an
//       unregistered OID means a length/heuristic-derived classification -> error
//   P2  verdict 'unknown': raw OID preserved, nistQuantumSecurityLevel omitted
//   P3  signature verdict != subject-key verdict -> both reported (warning)
//   P4  pqSecure && !cnsa20Compliant (e.g. SLH-DSA category 5) -> warning.
//       2033-12-31 is the CNSA 2.0 exclusive-use date for large PKI systems
//       (brief §1.5, NSA CNSA 2.0 "Other requirements for NSS").
//   P5  deprecated classical algorithm -> one finding for the IR 8547 clock and,
//       when the key is provably below the CNSA 1.0 parameter floor
//       (RSA < 3072, ECDSA/ECDH P-256, EdDSA), a second, separate finding.
//       The two mandates are never collapsed (brief P5, spec EC-03).
//   P6  PQ leaf whose issuer classification is not quantum-resistant -> warning
//       at the issuer's deadline (chain is only as strong as its weakest link)
//   P7  deprecated asset whose notAfter is after 2035-12-31 -> expiry outlives
//       the IR 8547 disallowance. Not applied to PQ assets (no such date).
//   P8  ML-KEM with digitalSignature keyUsage -> error (FIPS 203 has no signing
//       operation; RFC 9935 §4 requires keyEncipherment)
//   P9  scope statement, exactly once per call: certificates and keys only;
//       hybrid TLS groups are outside a file scanner's view
//   P10 DER parser limit violation (indefinite length, depth > 128) -> error
//   P11 a record that carries key material -> error; the material is never
//       echoed into the finding (brief P11: a JSON field with a key is a breach)
//   P12 notAfter that is not an absolute UTC timestamp -> error; the value is
//       not used for a deadline verdict (brief P12: no naive local-time parsing)
//
// Determinism (S-14): records are processed in input order and rules in the
// fixed order above, so the same input yields byte-identical output.

'use strict';

const { OID_TABLE, CLASSICAL_OIDS } = require('./constants');

const SEVERITIES = Object.freeze(['error', 'warning', 'info']);
const VERDICTS = Object.freeze(['compliant', 'deprecated', 'disallowed', 'unknown']);

// CNSA 2.0 exclusive-use date for large public-key infrastructure systems
// (brief §1.5 evidence block: "large public-key infrastructure systems ...
// exclusively use CNSA 2.0 by 2033"). Used for P4, never for classical assets.
const CNSA_2_ADOPTION_DATE = '2033-12-31';
// NIST IR 8547 Tables 2/4: classical algorithms deprecated after 2030,
// disallowed after 2035.
const IR8547_DEPRECATION_DATE = '2030-12-31';
const IR8547_DISALLOWANCE_DATE = '2035-12-31';

const DER_MAX_DEPTH = 128; // spec §2 DER parsing limits
const KEY_MATERIAL_FIELDS = Object.freeze(['keyBytes', 'privateKey', 'secretKey', 'seed']);

const FINDING_SCHEMA = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://pqblocks.local/schemas/finding-1.0.json',
  title: 'PQBlocks CNSA 2.0 finding (S-13, separate from the CycloneDX CBOM)',
  type: 'object',
  additionalProperties: false,
  required: ['ruleId', 'severity', 'assetRef', 'deadline', 'message'],
  properties: {
    ruleId: { type: 'string', pattern: '^P([1-9]|1[0-2])$' },
    severity: { type: 'string', enum: SEVERITIES },
    assetRef: { type: 'string', minLength: 1 },
    deadline: { type: 'string', pattern: '^(\\d{4}-\\d{2}-\\d{2}|immediate|N/A)$' },
    message: { type: 'string', minLength: 1 },
    mandate: { type: 'string', minLength: 1 },
  },
});

const FINDINGS_SCHEMA = Object.freeze({
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://pqblocks.local/schemas/findings-1.0.json',
  title: 'PQBlocks CNSA 2.0 findings array (S-13)',
  type: 'array',
  items: FINDING_SCHEMA,
});

class InvalidFindingsError extends TypeError {
  constructor(message) {
    super(message);
    this.name = 'InvalidFindingsError';
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isRegisteredOid(oid) {
  return (
    typeof oid === 'string' &&
    (Object.prototype.hasOwnProperty.call(OID_TABLE, oid) ||
      Object.prototype.hasOwnProperty.call(CLASSICAL_OIDS, oid))
  );
}

// Strings sort lexicographically in ISO-8601; pick the earlier real date.
function earliestDeadline(...values) {
  const dates = values.filter((v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v)).sort();
  return dates.length ? dates[0] : 'N/A';
}

// Returns { absolute, date }. A Date (the DER parser's output) is absolute;
// a string is absolute only when it carries an explicit Z/±hh:mm offset.
function readTimestamp(value) {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime())
      ? { absolute: false, date: null }
      : { absolute: true, date: value };
  }
  if (typeof value === 'string') {
    const explicitZone = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i.test(value);
    const date = new Date(value);
    if (explicitZone && !Number.isNaN(date.getTime())) return { absolute: true, date };
    return { absolute: false, date: null };
  }
  return { absolute: false, date: null };
}

function label(record) {
  return record.parameterSetIdentifier || record.family || record.oid || record.assetRef;
}

// True when the key is provably at or above the CNSA 1.0 floor. When the
// parameter set cannot be determined we return true: the emitter must not claim
// a floor breach it cannot prove (honest-framing rule).
function meetsCnsa1Floor(record) {
  const ps = record.parameterSetIdentifier;
  if (record.family === 'RSA') {
    const m = typeof ps === 'string' ? ps.match(/^RSA-(\d+)$/) : null;
    return m ? Number(m[1]) >= 3072 : true;
  }
  if (record.family === 'ECDSA' || record.family === 'EC') {
    if (ps === 'P-256') return false; // provably below P-384
    return true; // P-384/P-521 or undetermined
  }
  if (record.family === 'EdDSA') return false; // Ed25519/Ed448 are not in CNSA 1.0
  return true;
}

function normalizeRecord(record, index) {
  if (!isPlainObject(record)) {
    throw new InvalidFindingsError(
      `emitFindings expects classification objects, got ${record === null ? 'null' : typeof record} at index ${index}`,
    );
  }
  if (typeof record.verdict !== 'string' || !VERDICTS.includes(record.verdict)) {
    throw new InvalidFindingsError(
      `classification at index ${index} has no valid verdict (expected ${VERDICTS.join('|')}, got ${JSON.stringify(record.verdict)})`,
    );
  }
  const oid = typeof record.oid === 'string' && record.oid.length > 0 ? record.oid : null;
  const candidate = record.assetRef || record.file || oid;
  if (typeof candidate !== 'string' || candidate.length === 0) {
    throw new InvalidFindingsError(
      `classification at index ${index} has neither an oid nor an assetRef; a finding needs a stable asset reference`,
    );
  }
  return { ...record, oid, assetRef: candidate };
}

function finding(ruleId, severity, assetRef, deadline, message, mandate) {
  const f = { ruleId, severity, assetRef, deadline, message };
  if (mandate) f.mandate = mandate;
  return f;
}

function emitForRecord(record, out) {
  const ref = record.assetRef;
  const name = label(record);

  // P1 — OID-derived classification invariant.
  if (record.verdict !== 'unknown' && !isRegisteredOid(record.oid)) {
    out.push(
      finding(
        'P1',
        'error',
        ref,
        record.deadline || 'N/A',
        `Verdict "${record.verdict}" is not backed by an OID-registry entry (${record.oid || 'no OID'}); classification must be derived from the OID registry, never from key length`,
      ),
    );
  }

  // P2 — unknown OID: raw OID preserved, no quantum-security level.
  if (record.verdict === 'unknown') {
    out.push(
      finding(
        'P2',
        'error',
        ref,
        'N/A',
        `OID ${record.oid || '(none)'} is unknown to the registry; reported as unknown with the raw OID preserved and nistQuantumSecurityLevel omitted (0 would falsely mean "no category met")`,
      ),
    );
  }

  // P3 — signature and subject-key verdicts are two verdicts.
  const keyCls = record.keyClassification;
  if (isPlainObject(keyCls) && typeof keyCls.verdict === 'string' && keyCls.verdict !== record.verdict) {
    out.push(
      finding(
        'P3',
        'warning',
        ref,
        earliestDeadline(record.deadline, keyCls.deadline),
        `Signature algorithm ${name} is ${record.verdict} but the subject public key is ${keyCls.parameterSetIdentifier || keyCls.family || keyCls.oid} (${keyCls.verdict}); both verdicts must be reported and the estate takes the worse one`,
      ),
    );
  }

  // P4 — PQ is not the same as CNSA 2.0.
  if (record.pqSecure === true && record.cnsa20Compliant === false) {
    out.push(
      finding(
        'P4',
        'warning',
        ref,
        CNSA_2_ADOPTION_DATE,
        `PQ algorithm ${name} is quantum-resistant but not in CNSA 2.0 Table IV (category 5 is not CNSA 2.0 compliance); large PKI systems must exclusively use CNSA 2.0 by 2033`,
        'CNSA 2.0',
      ),
    );
  }

  // P5 — the two mandates disagree on classical algorithms: two findings.
  if (record.verdict === 'deprecated') {
    const deadline = /^\d{4}-\d{2}-\d{2}$/.test(record.deadline || '')
      ? record.deadline
      : IR8547_DEPRECATION_DATE;
    out.push(
      finding(
        'P5',
        'warning',
        ref,
        deadline,
        `Classical algorithm ${name} is deprecated after 2030 and disallowed after 2035 under NIST IR 8547 Tables 2/4`,
        'NIST IR 8547',
      ),
    );
    if (!meetsCnsa1Floor(record)) {
      out.push(
        finding(
          'P5',
          'error',
          ref,
          'immediate',
          `Classical algorithm ${name} is already below the CNSA 1.0 parameter floor (RSA >= 3072-bit modulus, ECDSA/ECDH P-384, no EdDSA); acceptable under IR 8547 until 2030 but not under the NSA floor`,
          'CNSA 1.0',
        ),
      );
    }
  }

  // P6 — chain, not leaf.
  const issuer = record.issuerClassification;
  if (isPlainObject(issuer) && issuer.pqSecure === false) {
    out.push(
      finding(
        'P6',
        'warning',
        ref,
        /^\d{4}-\d{2}-\d{2}$/.test(issuer.deadline || '') ? issuer.deadline : IR8547_DEPRECATION_DATE,
        `Asset is ${record.verdict} but its issuer is ${issuer.verdict} (${issuer.parameterSetIdentifier || issuer.family || 'unknown'}); the path still depends on a classical signature, so the chain verdict is the weakest link`,
      ),
    );
  }

  // P7 / P12 — expiry against the disallowance, using DER-decoded UTC only.
  const ts = readTimestamp(record.notAfter);
  if (record.notAfter !== undefined && record.notAfter !== null && !ts.absolute) {
    out.push(
      finding(
        'P12',
        'error',
        ref,
        'immediate',
        `notAfter ${JSON.stringify(record.notAfter)} is not an absolute UTC timestamp; parse UTCTime/GeneralizedTime from DER instead of local-time string parsing, and this value was not used for a deadline verdict`,
      ),
    );
  }
  if (ts.absolute && record.verdict === 'deprecated') {
    const disallowance = new Date(`${IR8547_DISALLOWANCE_DATE}T23:59:59Z`);
    if (ts.date.getTime() > disallowance.getTime()) {
      out.push(
        finding(
          'P7',
          'error',
          ref,
          IR8547_DISALLOWANCE_DATE,
          `Certificate notAfter ${ts.date.toISOString().slice(0, 10)} is after the IR 8547 disallowance date ${IR8547_DISALLOWANCE_DATE}; the expiry outlives the mandate`,
        ),
      );
    }
  }

  // P8 — a KEM cannot sign.
  const keyFamily = isPlainObject(keyCls) ? keyCls.family : null;
  if (
    (record.family === 'ML-KEM' || keyFamily === 'ML-KEM') &&
    Array.isArray(record.keyUsage) &&
    record.keyUsage.includes('digitalSignature')
  ) {
    out.push(
      finding(
        'P8',
        'error',
        ref,
        'immediate',
        `ML-KEM is a KEM (FIPS 203 defines KeyGen/Encaps/Decaps only) and cannot sign; keyUsage digitalSignature is invalid — RFC 9935 §4 requires keyEncipherment`,
      ),
    );
  }

  // P10 — DER hardening telemetry must never be silently accepted.
  const der = isPlainObject(record.der) ? record.der : null;
  if (der && der.indefiniteLength === true) {
    out.push(
      finding(
        'P10',
        'error',
        ref,
        'immediate',
        `DER input used an indefinite length; the hardened parser must reject it (bounded depth ${DER_MAX_DEPTH}, no indefinite lengths)`,
      ),
    );
  } else if (der && typeof der.depth === 'number' && der.depth > DER_MAX_DEPTH) {
    out.push(
      finding(
        'P10',
        'error',
        ref,
        'immediate',
        `DER nesting depth ${der.depth} exceeds the parser bound of ${DER_MAX_DEPTH}`,
      ),
    );
  }

  // P11 — key material must never reach an audited artefact.
  for (const field of KEY_MATERIAL_FIELDS) {
    const value = record[field];
    const hasMaterial =
      Buffer.isBuffer(value) ? value.length > 0 : typeof value === 'string' ? value.length > 0 : false;
    if (hasMaterial) {
      out.push(
        finding(
          'P11',
          'error',
          ref,
          'immediate',
          `Record carried key material (field: ${field}); the material was suppressed and never emitted. Output may contain only OIDs, lengths, DNs, validity and hashes`,
        ),
      );
      break;
    }
  }
}

function scopeFinding() {
  return finding(
    'P9',
    'info',
    'scan',
    'N/A',
    'Scope is certificates and keys on disk only; hybrid TLS key-exchange groups (e.g. X25519MLKEM768) are not visible to a file-based certificate auditor and no estate-wide quantum-readiness percentage is implied',
  );
}

/**
 * Validate a findings array against FINDING_SCHEMA (closed object: extra fields
 * are rejected, which is what keeps findings out of the CBOM's
 * `additionalProperties: false` properties).
 * @param {Array} findings
 * @returns {Array} the same array, for chaining
 */
function validateFindings(findings) {
  if (!Array.isArray(findings)) {
    throw new InvalidFindingsError(`findings must be an array, got ${typeof findings}`);
  }
  const allowed = new Set(Object.keys(FINDING_SCHEMA.properties));
  const required = FINDING_SCHEMA.required;
  findings.forEach((f, i) => {
    if (!isPlainObject(f)) throw new InvalidFindingsError(`finding ${i} is not an object`);
    for (const key of Object.keys(f)) {
      if (!allowed.has(key)) {
        throw new InvalidFindingsError(`finding ${i} has field "${key}" which is not in the findings schema`);
      }
    }
    for (const key of required) {
      if (f[key] === undefined || f[key] === null) {
        throw new InvalidFindingsError(`finding ${i} is missing required field "${key}"`);
      }
    }
    if (!/^P([1-9]|1[0-2])$/.test(f.ruleId)) {
      throw new InvalidFindingsError(`finding ${i} has invalid ruleId "${f.ruleId}"`);
    }
    if (!SEVERITIES.includes(f.severity)) {
      throw new InvalidFindingsError(`finding ${i} has invalid severity "${f.severity}"`);
    }
    if (typeof f.assetRef !== 'string' || f.assetRef.length === 0) {
      throw new InvalidFindingsError(`finding ${i} has an empty assetRef`);
    }
    if (!/^(\d{4}-\d{2}-\d{2}|immediate|N\/A)$/.test(f.deadline)) {
      throw new InvalidFindingsError(`finding ${i} has invalid deadline "${f.deadline}"`);
    }
    if (typeof f.message !== 'string' || f.message.length === 0) {
      throw new InvalidFindingsError(`finding ${i} has an empty message`);
    }
    if (f.mandate !== undefined && (typeof f.mandate !== 'string' || f.mandate.length === 0)) {
      throw new InvalidFindingsError(`finding ${i} has an invalid mandate`);
    }
  });
  return findings;
}

/**
 * @param {Array<object>} classifications classification records (see header)
 * @returns {Array<{ruleId:string,severity:string,assetRef:string,deadline:string,message:string,mandate?:string}>}
 */
function emitFindings(classifications) {
  if (!Array.isArray(classifications)) {
    throw new InvalidFindingsError(
      `emitFindings expects an array of classification objects, got ${classifications === null ? 'null' : typeof classifications}`,
    );
  }
  const findings = [];
  classifications.forEach((record, i) => {
    emitForRecord(normalizeRecord(record, i), findings);
  });
  findings.push(scopeFinding());
  return validateFindings(findings);
}

module.exports = {
  emitFindings,
  validateFindings,
  FINDING_SCHEMA,
  FINDINGS_SCHEMA,
  InvalidFindingsError,
  CNSA_2_ADOPTION_DATE,
  IR8547_DEPRECATION_DATE,
  IR8547_DISALLOWANCE_DATE,
};
