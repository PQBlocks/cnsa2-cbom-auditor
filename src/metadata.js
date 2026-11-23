'use strict';

// S-15: Mandate citation metadata
// Contract: lib/metadata.js injects metadata.properties into CBOM
// Metadata:
//   cnsa2:mandate      (PP-22-1338)      → NSA CNSA 2.0 (U/OO/194427-22, SEP 2022 v1.0)
//   nist:transition    (IR 8547 Oct 2026) → NIST IR 8547 (October 2026) Tables 2 and 4
//   classification:oracle (OpenSSL 3.6.5) → OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026)

const MANDATE_PROPS = [
  { name: 'cnsa2:mandate', value: 'NSA CNSA 2.0 (U/OO/194427-22, SEP 2022 v1.0)' },
  { name: 'nist:transition', value: 'NIST IR 8547 (October 2026) Tables 2 and 4' },
];

function injectMetadata(metadata, oracle = 'OpenSSL 3.6.5 29 Sep 2026 (Library: OpenSSL 3.6.5 29 Sep 2026)') {
  if (!Array.isArray(metadata.properties)) metadata.properties = [];

  // Remove any existing mandate properties to avoid duplication
  metadata.properties = metadata.properties.filter(p => !['cnsa2:mandate', 'nist:transition', 'classification:oracle'].includes(p.name));

  metadata.properties.push(
    { name: 'cnsa2:mandate', value: 'NSA CNSA 2.0 (U/OO/194427-22, SEP 2022 v1.0)' },
    { name: 'nist:transition', value: 'NIST IR 8547 (October 2026) Tables 2 and 4' },
    { name: 'classification:oracle', value: oracle }
  );

  return metadata;
}

function getMandateProperties() {
  return [
    { name: 'cnsa2:mandate', value: 'PP-22-1338' },
    { name: 'nist:transition', value: 'IR 8547 Oct 2026' },
    { name: 'classification:oracle', value: 'OpenSSL 3.6.5' },
  ];
}

module.exports = {
  injectMetadata,
  getMandateProperties,
};