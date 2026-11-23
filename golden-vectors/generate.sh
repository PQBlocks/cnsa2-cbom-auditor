#!/usr/bin/env bash
# Regenerate the golden-vector certificate set for pqblocks-cnsa-evidence.
#
# Provenance: every certificate is produced by the locally installed OpenSSL
# (version printed at the end) using only FIPS-approved / FIPS 203-205 key
# types.  Private keys are generated into $TMP and are NOT shipped: the auditor
# under test only ever sees public artefacts, so shipping keys would add risk
# with no test value.
#
# The expected classification for each file is NOT written here.  It is derived
# independently from `openssl x509 -text` by derive-expected.mjs, so the oracle
# is OpenSSL + the FIPS tables, never the product's own classifier.
set -euo pipefail
cd "$(dirname "$0")"

OPENSSL=${OPENSSL:-openssl}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p certs spki

mk() { # mk <name> <keygen-args...> -- <req-args...>
  local name=$1; shift
  local keyargs=() reqargs=()
  while [ "$1" != "--" ]; do keyargs+=("$1"); shift; done
  shift
  reqargs=("$@")
  "$OPENSSL" genpkey "${keyargs[@]}" -out "$TMP/$name.key"
  "$OPENSSL" req -new -x509 -key "$TMP/$name.key" -days 3650 \
      -subj "/CN=pqblocks-gv-$name" -set_serial "0x$(printf '%s' "$name" | sha256sum | cut -c1-16)" \
      -out "certs/$name.crt" "${reqargs[@]}"
  "$OPENSSL" pkey -in "$TMP/$name.key" -pubout -out "spki/$name.spki.pem"
}

mk rsa2048-sha256  -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -- -sha256
mk rsa3072-sha384  -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -- -sha384
mk rsa4096-sha512  -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -- -sha512
mk ec-p256-sha256  -algorithm EC  -pkeyopt ec_paramgen_curve:P-256 -- -sha256
mk ec-p384-sha384  -algorithm EC  -pkeyopt ec_paramgen_curve:P-384 -- -sha384
mk ed25519         -algorithm ED25519 --
mk mldsa44         -algorithm ml-dsa-44 --
mk mldsa65         -algorithm ml-dsa-65 --
mk mldsa87         -algorithm ml-dsa-87 --
mk slhdsa-sha2-128s  -algorithm slh-dsa-sha2-128s --
mk slhdsa-shake-256f -algorithm slh-dsa-shake-256f --

# A KEM public key has no certificate form (it cannot sign a CSR): ship the raw
# SubjectPublicKeyInfo instead.  RFC 9935 defines exactly this encoding.
"$OPENSSL" genpkey -algorithm ml-kem-1024 -out "$TMP/mlkem1024.key"
"$OPENSSL" pkey -in "$TMP/mlkem1024.key" -pubout -out "spki/mlkem1024.spki.pem"

echo "generated $(ls certs/*.crt | wc -l) certs, $(ls spki/*.pem | wc -l) SPKIs with $("$OPENSSL" version)"
