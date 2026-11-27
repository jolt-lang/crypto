# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Each version is a git tag, so a dependency pins it with `:git/tag` and the
matching `:git/sha`.

## [Unreleased]

### Added

- **Buddy-compatible OpenSSL APIs under `jolt.crypto`.** Ported byte and codec
  helpers; MD5, SHA-1, SHA-256/384/512, SHA-3, BLAKE2b-512 and RIPEMD-160
  hashes; HMAC and AES-Poly1305; HKDF, KDF1/KDF2, counter/feedback/double-pipeline KDF and
  PBKDF2; AES ECB/CBC/CTR/OFB/GCM, original ChaCha, and authenticated
  AES-CBC-HMAC-SHA2/AES-GCM; RSA PKCS#1/PSS, ECDSA and EdDSA signatures; PEM,
  JWK and RFC 3394 key wrapping; X.509 helpers; ECDSA transcoding; and DEFLATE.
  Buddy Core's tests and fixtures were ported with the implementation.
- `NOTICE` and `LICENSE-buddy-core` preserve Buddy Core's Apache 2.0
  attribution and the Nimbus JOSE + JWT attribution for ECDSA transcoding.
- The README maps every delivered namespace, lists supported algorithms and
  explicit deferrals, and documents OpenSSL 3 requirements, native cipher
  cleanup, ignored signature `:prng`, and bounded n/e/d-only RSA recovery.
- Tiger, Whirlpool, RIPEMD-128/256/320, BLAKE3, Skein, BLAKE2b-128/256,
  Twofish, Serpent, and their dependent variants are explicitly deferred rather
  than approximated with incompatible implementations.

## [0.3.0] - 2026-11-26

### Added

- **`jolt.crypto.x509`, a certificate builder** (#19, closes #20). The JDK has
  no public X.509 builder to mirror, so this is a set of functions in its own
  namespace. `certificate` signs a v3 certificate for a `PublicKey` you
  already have, `generate` makes the key pair as well and returns
  `{:certificate :private-key}`, and `pem` writes PEM for a certificate, a
  PKCS#8 private key or an SPKI public key. The result is the same
  `X509Certificate` that `CertificateFactory` returns. `generate` covers a
  self-signed localhost certificate and a small CA plus the leaves it issues,
  for mTLS tests, so a test server no longer has to shell out to
  `openssl req`. The signing key picks SHA256withRSA, SHA256withECDSA or
  Ed25519, and the default key is P-256. Bad input (an unknown option, a
  malformed DN, a bad IP or DNS name, an issuer that isn't a CA, a key that
  doesn't match) throws an `ex-info` naming the problem. The README lists
  what isn't supported: quoted or multi-valued RDNs, `#hex` DN values,
  `pathLenConstraint`, and checking validity against the issuer's.
- CI lints with jolt-lsp (#21).

## [0.2.1] - 2026-11-09

### Fixed

- **The OpenSSL natives are `:optional`** (#18). jolt loads every
  dependency's natives at startup, whether or not anything requires the
  namespace that uses them, so any app with this library in its tree refused
  to start on a host without OpenSSL. ring-chez-adapter carries it for
  ring-defaults, which made that every plain web server. The app now starts,
  and a crypto call fails when it's made.
- The README's deps example uses the current repo URL (#17).

## [0.2.0] - 2026-10-15

The same code as 0.1.0, tagged on the merge of #16.

## [0.1.0] - 2026-10-07

### Added

- **Ed25519** in `Signature`, `KeyFactory` and `KeyPairGenerator`, under both
  `Ed25519` and `EdDSA` (#16).

## [0.0.11] - 2026-10-02

### Removed

- The `:link-libs` key from `deps.edn`. jolt 0.8.16 links what a static
  `libcrypto.a` needs on its own, so the key did nothing.

## [0.0.10] - 2026-10-01

### Fixed

- **macOS no longer falls back to Apple's libcrypto stub.** The last macOS
  candidates resolved to `/usr/lib/libcrypto.dylib`, which aborts the process
  that opens it, so a machine without OpenSSL died with "loading libcrypto in
  an unsafe way". The candidates are now the Homebrew (arm64 and Intel) and
  MacPorts paths and the versioned bare names, and with none present jolt
  reports the library as missing.

## [0.0.9] - 2026-09-29

### Fixed

- **The `off`/`len` overloads honor their window** (#12). `MessageDigest.update`,
  `Signature.update` and `Cipher.doFinal` used to hash or encrypt the whole
  array, so a streaming read loop calling `update(buf, 0, n)` hashed the stale
  tail of every short read. `MessageDigest.digest(buf, off, len)` and
  `Mac.doFinal(out, off)` now write into the caller's buffer, and `Mac` gained
  `update`. The `SecretKeySpec`, `IvParameterSpec` and `Signature.verify`
  windows are honored too, and `SecretKeySpec.getAlgorithm` returns the
  algorithm it was given instead of always `AES`.

## [0.0.8] - 2026-09-18

### Added

- **X.509 parsing.** `CertificateFactory` reads one certificate or a bundle
  from PEM or DER. `X509Certificate` and `X500Principal` answer the way the
  JDK's do for the same bytes.
- `:windows` candidates for libcrypto and libssl.

## [0.0.7] - 2026-09-10

### Added

- **RSA** key generation, signatures and key parsing.

### Fixed

- A `Signature` or `KeyFactory` refuses a key of another algorithm, as on the
  JVM. Before, `SHA256withRSA` given an EC key produced an ECDSA signature,
  and an EC `KeyFactory` accepted RSA DER.

## [0.0.6] - 2026-09-04

### Fixed

- Large inputs no longer accumulate as boxed values.

## [0.0.5] - 2026-09-02

### Changed

- **Requires jolt 0.8.0**, where `jolt.ffi/write` takes its value before the
  offset. An older jolt would write to the wrong place without any error, so
  `deps.edn` declares `:jolt/min-version "0.8.0"`.

### Added

- `deps.edn` declares the JDK classes this library provides (`:jolt/provides`,
  #6), so a JVM library that reaches for `MessageDigest/getInstance` loads it
  on first reference. SecureRandom is left out because jolt implements it
  natively.

## [0.0.4] - 2026-08-22

### Fixed

- `MessageDigest.digest(bytes)` adds `bytes` to what was already fed with
  `update`, as on the JVM. It used to hash only the final piece, which gave
  wrong namespaced v3/v5 UUIDs in clj-uuid.

## [0.0.3] - 2026-08-18

### Added

- **EC** key generation, and ECDSA signing and verification.
- The rest of `SecureRandom`: `nextInt`, `nextLong`, `nextDouble`,
  `nextFloat`, `nextBoolean`, `setSeed`, `getInstance` and
  `getInstanceStrong`, all over `RAND_bytes`. `nextInt(bound)` uses rejection
  sampling instead of a biased modulo.
- The EPL-2.0 licence.

## [0.0.2] - 2026-07-31

### Added

- The rest of the SHA-2 family in `MessageDigest` and `Mac`.

## [0.0.1] - 2026-06-26

### Added

- First release: AES/CBC, HMAC, SHA digests, MD5 and `SecureRandom` over
  OpenSSL, through the `javax.crypto` / `java.security` classes.

[Unreleased]: https://github.com/jolt-lang/crypto/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jolt-lang/crypto/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/jolt-lang/crypto/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/jolt-lang/crypto/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jolt-lang/crypto/compare/v0.0.11...v0.1.0
[0.0.11]: https://github.com/jolt-lang/crypto/compare/v0.0.10...v0.0.11
[0.0.10]: https://github.com/jolt-lang/crypto/compare/v0.0.9...v0.0.10
[0.0.9]: https://github.com/jolt-lang/crypto/compare/v0.0.8...v0.0.9
[0.0.8]: https://github.com/jolt-lang/crypto/compare/v0.0.7...v0.0.8
[0.0.7]: https://github.com/jolt-lang/crypto/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/jolt-lang/crypto/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/jolt-lang/crypto/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/jolt-lang/crypto/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/jolt-lang/crypto/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/jolt-lang/crypto/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/jolt-lang/crypto/releases/tag/v0.0.1
