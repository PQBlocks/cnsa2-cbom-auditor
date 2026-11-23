# tests/fixtures — provenance for S-11 bundle fixtures

Generated locally with **OpenSSL 3.6.5** (same toolchain as golden-vectors/).
No fixture is hand-written and none is produced by the product under test.

| file | what it is | command |
|---|---|---|
| `bundle.p7b.pem` | PKCS#7 SignedData bundle carrying three golden certificates | `openssl crl2pkcs7 -nocrl -certfile golden-vectors/certs/rsa2048-sha256.crt -certfile golden-vectors/certs/ec-p256-sha256.crt -certfile golden-vectors/certs/ed25519.crt -outform PEM -out tests/fixtures/bundle.p7b.pem` |
| `encrypted.pfx` | encrypted PKCS#12 (PFX) exported from a throwaway RSA-2048 key; passphrase `fixture-pass` | `openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 3650 -nodes -subj "/CN=pqblocks-fixture-pfx"` then `openssl pkcs12 -export -in c.pem -inkey k.pem -out tests/fixtures/encrypted.pfx -passout pass:fixture-pass` |
| `encrypted-pkcs12.pem` | the same PFX, base64-armoured under a `PKCS12` PEM label | `base64 -w64 tests/fixtures/encrypted.pfx \| sed -e '1i-----BEGIN PKCS12-----' -e '$a-----END PKCS12-----'` |
| `multi.pem` | three certificate blocks plus one SPKI block, concatenated | `cat golden-vectors/certs/{rsa2048-sha256,ec-p256-sha256,ed25519}.crt golden-vectors/spki/mldsa87.spki.pem` |

Verification of the bundle contents (independent of the product):

```
$ openssl pkcs7 -in tests/fixtures/bundle.p7b.pem -print_certs -noout
subject=CN=pqblocks-gv-rsa2048-sha256
issuer=CN=pqblocks-gv-rsa2048-sha256

subject=CN=pqblocks-gv-ec-p256-sha256
issuer=CN=pqblocks-gv-ec-p256-sha256

subject=CN=pqblocks-gv-ed25519
issuer=CN=pqblocks-gv-ed25519
```

```
$ openssl pkcs12 -in tests/fixtures/encrypted.pfx -passin pass:fixture-pass -nokeys 2>/dev/null | grep subject=
subject=CN=pqblocks-fixture-pfx
```
