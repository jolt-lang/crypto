# Buddy-Compatible OpenSSL API Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Buddy-compatible `jolt.crypto` APIs and ported tests for every supported OpenSSL algorithm, while explicitly deferring algorithms OpenSSL cannot reproduce faithfully.

**Architecture:** Extend the repository's OpenSSL FFI foundation and expose Buddy's protocols and option-map APIs through Jolt engine values. Reuse existing host key/certificate values, use Clojure for format conversions and KDF constructions, and integrate all ported tests with the existing `jolt -M:test` runner.

**Tech Stack:** Jolt/Clojure, Chez Scheme host shims, `jolt.ffi`, OpenSSL 3 default provider, `clojure.test`, `org.clojure/test.check` for DEFLATE properties.

**Spec:** `docs/superpowers/specs/2026-11-26-buddy-core-openssl-port-design.md`

## Global Constraints

- Map `buddy.core.*` to `jolt.crypto.*` and `buddy.util.*` to `jolt.crypto.util.*`.
- Use OpenSSL 3 default-provider algorithms only; no Bouncy Castle, JVM libraries, reflection, placeholders, or truncated substitutes for distinct algorithms.
- Defer Tiger, Whirlpool, RIPEMD-128/256/320, BLAKE3, Skein, BLAKE2b-128/256, Twofish, Serpent, and their dependent variants.
- Preserve existing `jolt.crypto` and `jolt.crypto.x509` behavior and tests.
- Retain Apache 2.0 and Nimbus attribution, add modification notices, and copy the applicable license text.
- Do not add the existing untracked `.clj-kondo/` or `.lsp/` directories.
- Work on `feat/buddy-core-openssl-port`; do not push or open the PR until the entire suite and lint checks pass.
- Run tests from the repository root with `JOLT_PWD="$PWD" jolt -M:test`; expected success includes `ALL CRYPTO TESTS PASSED` and zero `clojure.test` failures/errors.

## Review Focus

- Malformed hex/Base64 and invalid algorithm names must fail explicitly rather than return nil, truncate input, or select another algorithm; pin in Tasks 1 and 3.
- Split stream reads and offset/length updates must consume exactly the requested bytes and reset engines correctly; pin in Tasks 3, 4, 6, and 9.
- Invalid padding, wrong passwords, malformed keys, and wrong key types must throw without returning partial values or leaking native resources; pin in Tasks 2 and 8.
- Modified ciphertext, AAD, IV, or authentication tags must fail verification before plaintext is returned; pin in Task 7.
- RSA/EC/OKP JWK values must preserve unsigned big integers, leading-zero coordinates, canonical thumbprint field order, and private/public consistency; pin in Task 10.
- Empty and large binary inputs, including NUL bytes, must round-trip through codecs, hashes, ciphers, and DEFLATE; pin in Tasks 1, 3, 7, and 12.

---

### Task 1: Branch, Attribution, Bytes, and Codecs

**Files:**
- Create: `NOTICE`, `LICENSE-buddy-core`
- Create: `src/jolt/crypto/bytes.clj`, `src/jolt/crypto/codecs.clj`, `src/jolt/crypto/codecs/base64.clj`
- Create: `test/jolt/crypto/bytes_test.clj`, `test/jolt/crypto/codecs_test.clj`
- Create: `test/_files/*` copied unchanged from `/Users/yogthos/src/buddy-core/test/_files`
- Modify: `test/jolt/crypto_test.clj` to run registered Buddy-style `clojure.test` namespaces in addition to existing checks
- Add: `docs/superpowers/specs/2026-11-26-buddy-core-openssl-port-design.md`, this plan

**Interfaces:**
- Produces: `bytes/bytes?`, `fill!`, `slice`, `copy`, `equals?`, `concat`.
- Produces: `codecs/IByteArray`, `to-bytes`, `->bytes`, string/hex/Base64 converters, `long->bytes`, `bytes->long`, and deprecated Base64 aliases.
- Produces: `base64/encode [data] [data urlsafe?]` and `base64/decode [data] [data urlsafe?]` returning byte arrays.
- Later tasks consume byte arrays and `codecs/to-bytes`; no Java array class or Apache Commons Codec is used.

- [ ] **Step 1: Create the feature branch**

Run: `git switch -c feat/buddy-core-openssl-port`
Expected: branch created from clean `main`; pre-existing untracked tooling directories remain uncommitted.

- [ ] **Step 2: Port the failing byte and codec tests**

Port Buddy's codec assertions and add byte tests for copy independence, ranged fills, signed bytes, empty input, `long` round trips, malformed hex, invalid Base64, and constant-time equality's unequal-length result. Register the two namespaces in the test runner.

- [ ] **Step 3: Run the tests to verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL while resolving `jolt.crypto.bytes` or `jolt.crypto.codecs`.

- [ ] **Step 4: Implement the namespaces and attribution**

Port the public functions and protocols with Jolt byte arrays, `java.util.Base64`, `ByteBuffer`, bulk array copies, and non-short-circuiting XOR equality. Preserve arities/defaults and reject malformed encodings. Add Buddy's Apache license, source revision `9763a3f`, copyright/modification notices, and copy all test fixtures unchanged.

- [ ] **Step 5: Run tests and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: new codec/byte tests and all existing tests PASS.

```bash
git add NOTICE LICENSE-buddy-core src/jolt/crypto/bytes.clj src/jolt/crypto/codecs.clj src/jolt/crypto/codecs/base64.clj test/jolt/crypto/bytes_test.clj test/jolt/crypto/codecs_test.clj test/jolt/crypto_test.clj test/_files docs/superpowers
git commit -m "feat: add Buddy-compatible bytes and codecs"
```

### Task 2: Padding and Nonces

**Files:**
- Create: `src/jolt/crypto/padding.clj`, `src/jolt/crypto/nonce.clj`
- Create: `test/jolt/crypto/padding_test.clj`, `test/jolt/crypto/nonce_test.clj`
- Modify: `test/jolt/crypto_test.clj`

**Interfaces:**
- Consumes: Task 1 `bytes` functions and existing `jolt.crypto/random-bytes`.
- Produces: `padding/padding-engine`, `pad!`, `pad`, `unpad`, `count`, `padded?` for `:pkcs7`, `:tbc`, `:zerobyte`.
- Produces: `nonce/random-bytes`, `random-nonce` with optional `SecureRandom`, and `for-engine`.

- [ ] **Step 1: Write failing tests**

Port all Buddy padding vectors. Add nonce tests for requested lengths, eight-byte big-endian timestamp prefix, random suffix, custom `SecureRandom`, unsupported padding, and malformed padding returning Buddy's zero count/unmodified unpad behavior.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving the new namespaces.

- [ ] **Step 3: Implement padding and nonce APIs**

Implement pure Clojure padding engines behind Buddy's operations, with mutation only in `pad!`. Use the existing CSPRNG and `ByteBuffer`; define engine nonce dispatch for the cipher types introduced later plus a block-size-based fallback.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: PASS, including empty and malformed padding cases.

```bash
git add src/jolt/crypto/padding.clj src/jolt/crypto/nonce.clj test/jolt/crypto/padding_test.clj test/jolt/crypto/nonce_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible padding and nonces"
```

### Task 3: OpenSSL Digest Engines

**Files:**
- Create: `src/jolt/crypto/internal/openssl.clj`, `src/jolt/crypto/hash.clj`
- Create: `test/jolt/crypto/hash_test.clj`
- Modify: `test/jolt/crypto_test.clj`

**Interfaces:**
- Produces internal: `openssl/digest-bytes [algorithm data]`, `openssl/hmac-bytes [algorithm key data]`, `openssl/digest-length [algorithm]`; algorithms are Buddy keywords and results are byte arrays.
- Produces: `hash/IDigest`, `IEngine`, `reset!`, `update!`, `end!`, `resolve-digest-engine`, `digest`, and supported named hash functions.
- Supported engine keys: `:md5`, `:sha1`, `:sha256`, `:sha384`, `:sha512`, `:sha3-256`, `:sha3-384`, `:sha3-512`, `:blake2b-512`, `:ripemd160`.

- [ ] **Step 1: Write failing digest tests**

Port Buddy's MD5/SHA/SHA3/BLAKE2b-512/RIPEMD-160 vectors, file hash, and low-level engine test. Add MD5 and SHA-256 known answers for `"abc"`, split and offset updates, engine reset/reuse, all supported input types, explicit rejection of every deferred hash, and rejection of `blake2b` lengths other than 64.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving `jolt.crypto.hash`.

- [ ] **Step 3: Implement generic OpenSSL digest/HMAC helpers and hash engines**

Bind digest lookup by exact OpenSSL name, output sizing, one-shot digest, and HMAC with bounded native allocations. Implement Buddy protocols over Jolt engine records, snapshotting update input and preserving stream semantics. Map only the supported keys; expose `blake2b` only for exact 64-byte BLAKE2b-512.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: all supported vectors PASS; deferred algorithms fail explicitly.

```bash
git add src/jolt/crypto/internal/openssl.clj src/jolt/crypto/hash.clj test/jolt/crypto/hash_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add OpenSSL-backed Buddy digest APIs"
```

### Task 4: HMAC and AES-Poly1305

**Files:**
- Create: `src/jolt/crypto/mac.clj`
- Create: `test/jolt/crypto/mac_test.clj`
- Modify: `src/jolt/crypto/internal/openssl.clj`, `test/jolt/crypto_test.clj`

**Interfaces:**
- Consumes: Task 3 digest helpers and engines, Task 1 constant-time equality.
- Produces: `mac/IMac`, `IEngineInit`, `IEngine`, `engine`, `resolve-cipher-engine`, `hash`, `verify`.
- Supported MACs: generic `:hmac`, `:hmac+sha1/sha256/sha384/sha512`, generic `:poly1305` with `:cipher :aes`, and `:poly1305+aes`.

- [ ] **Step 1: Write failing MAC tests**

Port all HMAC and AES-Poly1305 tests, retaining the large-key RFC vector and stream/file/URL/URI cases. Replace direct `SHA256Digest`/`HMac` construction with public Jolt engine constructors. Add known-answer AES-Poly1305 coverage, offset/reset checks, wrong-key/IV/signature failures, and explicit Twofish/Serpent rejection.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving `jolt.crypto.mac`.

- [ ] **Step 3: Implement MAC engines**

Use OpenSSL HMAC for generic and named HMACs. Implement Buddy's cipher-based Poly1305 construction exactly with AES and OpenSSL Poly1305, freeing key/cipher/MAC contexts in `finally`; do not substitute ChaCha20-Poly1305 or raw-key-only Poly1305 semantics.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: MAC vectors and verification cases PASS.

```bash
git add src/jolt/crypto/mac.clj src/jolt/crypto/internal/openssl.clj test/jolt/crypto/mac_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible MAC engines"
```

### Task 5: Key Derivation Functions

**Files:**
- Create: `src/jolt/crypto/kdf.clj`
- Create: `test/jolt/crypto/kdf_test.clj`
- Modify: `test/jolt/crypto_test.clj`

**Interfaces:**
- Consumes: Task 3 digest functions and Task 4 HMAC.
- Produces: `kdf/IKDF`, `engine`, `get-bytes`, `get-buffer`, `+pbkdf2-iterations+` (= 1000).
- Supported constructions: `:hkdf`, `:kdf1`, `:kdf2`, `:cmkdf`, `:fmkdf`, `:dpimkdf`, `:pbkdf2` and Buddy's named digest variants over supported digests.

- [ ] **Step 1: Write failing KDF tests**

Port every Buddy KDF vector, including the 16,777,216-iteration PBKDF2 case. Add HKDF empty salt/info, multi-block output, binary password/salt, default iterations, `ByteBuffer` contents, and counter/feedback/double-pipeline known answers.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving `jolt.crypto.kdf`.

- [ ] **Step 3: Implement KDF constructions**

Implement standards-compatible counter encoding, HKDF extract/expand, and feedback state using the earlier digest/HMAC interfaces. Bind OpenSSL's PBKDF2-HMAC operation so the 16,777,216-iteration vector runs natively within the test budget. Preserve Buddy option names, defaults, shorthand algorithm keys, and exact output lengths.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: all KDF vectors PASS within the normal test time budget.

```bash
git add src/jolt/crypto/kdf.clj test/jolt/crypto/kdf_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible KDF engines"
```

### Task 6: AES Modes and ChaCha Engines

**Files:**
- Create: `src/jolt/crypto/crypto.clj`
- Create: `test/jolt/crypto/crypto_test.clj`
- Modify: `src/jolt/crypto/internal/openssl.clj`, `src/jolt/crypto/nonce.clj`, `test/jolt/crypto_test.clj`

**Interfaces:**
- Consumes: Task 1 bytes, Task 2 padding/nonces.
- Produces: `crypto/ICipherInit`, `IBlockCipherLike`, `IStreamCipherLike`, `block-cipher`, `stream-cipher`, `init!`/`initialize!`, `process-block!`, `process-bytes!`, `end!`, sizing aliases, and `split-by-blocksize`.
- Supported low-level engines: AES `:ecb`, `:cbc`, `:ctr`/`:sic`, `:ofb`; ChaCha `:chacha` with Buddy's 64-bit nonce behavior. GCM is completed in Task 7.

- [ ] **Step 1: Write failing low-level cipher tests**

Port Buddy's AES-CBC and ChaCha known answers and stateful second-block/second-chunk cases, omitting only Twofish. Add AES ECB/CTR/OFB known answers, offsets, decrypt-after-reinitialize, block splitting, empty input, invalid key/IV sizes, and explicit Twofish/Serpent rejection.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving `jolt.crypto.crypto`.

- [ ] **Step 3: Implement stateful cipher engines**

Bind the exact EVP AES modes and ChaCha20, select key size from 16/24/32-byte keys, and preserve chaining/stream state across calls. Register `nonce/for-engine` methods for the concrete block and stream engine types. Native contexts must be released on reinitialization/finalization and all failure paths; never emulate a requested mode with CBC.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: exact low-level vectors and stateful calls PASS.

```bash
git add src/jolt/crypto/crypto.clj src/jolt/crypto/internal/openssl.clj src/jolt/crypto/nonce.clj test/jolt/crypto/crypto_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible AES and ChaCha engines"
```

### Task 7: GCM and High-Level Authenticated Encryption

**Files:**
- Modify: `src/jolt/crypto/crypto.clj`, `src/jolt/crypto/internal/openssl.clj`
- Modify: `test/jolt/crypto/crypto_test.clj`, `test/jolt/crypto_test.clj`

**Interfaces:**
- Consumes: Tasks 3–6 digest, HMAC, padding, bytes, and cipher APIs.
- Produces: AES `:gcm` low-level engines and `encrypt-cbc`, `decrypt-cbc`, `encrypt-gcm`, `decrypt-gcm`, `encrypt`, `decrypt`.
- High-level algorithms: `:aes128-cbc-hmac-sha256`, `:aes192-cbc-hmac-sha384`, `:aes256-cbc-hmac-sha512`, `:aes128-gcm`, `:aes192-gcm`, `:aes256-gcm`.

- [ ] **Step 1: Write failing authenticated-encryption tests**

Port Buddy's GCM sizing/finalization and all high-level round trips. Reduce only duplicated random-loop counts if needed for runtime, retaining every length from 1 through 99 at least once per algorithm. Add fixed GCM/CBC-HMAC vectors, AAD, empty input, truncated input, and tampered ciphertext/tag/AAD/IV tests asserting no plaintext return.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL in GCM/high-level tests.

- [ ] **Step 3: Implement GCM and high-level schemes**

Implement 128-bit GCM tags and Buddy's exact CBC-HMAC key splitting, AL encoding, truncated tags, and constant-time verification. Check authentication before CBC decryption and preserve Buddy's `ex-info` `:type`/`:cause` values.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: all encryption vectors, round trips, and tamper cases PASS.

```bash
git add src/jolt/crypto/crypto.clj src/jolt/crypto/internal/openssl.clj test/jolt/crypto/crypto_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible authenticated encryption"
```

### Task 8: PEM Keys and AES Key Wrapping

**Files:**
- Create: `src/jolt/crypto/keys.clj`, `src/jolt/crypto/keys/pem.clj`
- Create: `test/jolt/crypto/keys_test.clj`
- Modify: `src/jolt/crypto.clj`, `src/jolt/crypto/internal/openssl.clj`, `test/jolt/crypto_test.clj`

**Interfaces:**
- Produces: `keys/private-key`, `public-key`, string constructors, predicates, `wrap`, `unwrap`; PEM `read-privkey` and `read-pubkey`.
- Produces internal key decoding used by Tasks 9–11 while retaining existing tagged-table `PrivateKey`/`PublicKey` values and DER encodings.
- Supported PEM keys: RSA, DSA, EC, Ed25519, Ed448, encrypted traditional and PKCS#8 forms present in Buddy fixtures.

- [ ] **Step 1: Write failing PEM/key-wrap tests**

Port every Buddy key test, replacing Bouncy Castle class assertions with `.getAlgorithm`, `.getFormat`, predicates, DER round trips, and later sign/verify behavior. Keep missing/wrong passphrase cases and invalid wrapped-key lengths; add string/reader inputs, public keys extracted from certificates, and AES wrap known answers.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving `jolt.crypto.keys`.

- [ ] **Step 3: Implement PEM decoding and AES key wrap**

Use OpenSSL PEM decoders/password handling and DER key parsers, identifying algorithm from the decoded key rather than the filename. Extend key creation for DSA and Ed448 without changing existing RSA/EC/Ed25519 behavior. Bind RFC 3394 AES wrap/unwrap and validate all outputs before returning them.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: all key fixtures and wrapping tests PASS; bad passwords and malformed inputs throw.

```bash
git add src/jolt/crypto/keys.clj src/jolt/crypto/keys/pem.clj src/jolt/crypto.clj src/jolt/crypto/internal/openssl.clj test/jolt/crypto/keys_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible PEM and key wrapping"
```

### Task 9: Digital Signatures

**Files:**
- Create: `src/jolt/crypto/dsa.clj`
- Create: `test/jolt/crypto/dsa_test.clj`
- Modify: `src/jolt/crypto.clj`, `test/jolt/crypto_test.clj`

**Interfaces:**
- Consumes: Task 8 keys and existing `java.security.Signature` host shims.
- Produces: `dsa/IEngine`, `ISignature`, `sign`, `verify` and algorithm map entries for RSA PKCS#1/PSS, ECDSA, and EdDSA.
- Extends host shims with RSA-PSS SHA-256/384/512 and Ed448 while preserving all current signature algorithms.

- [ ] **Step 1: Write failing DSA tests**

Port every Buddy DSA test using Task 8 fixture keys. Add every documented digest variant, Ed25519 and Ed448 known answers, split stream/offset updates, wrong key/signature failures, RSA-PSS salt behavior, and explicit rejection of mismatched key algorithms.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving `jolt.crypto.dsa` or using RSA-PSS/Ed448.

- [ ] **Step 3: Implement signature engines and missing host algorithms**

Use the existing stateful `Signature` contract where possible. Configure OpenSSL RSA-PSS padding/MGF1 and Ed448 one-shot signing explicitly; free native contexts on all paths and preserve false rather than throw for ordinary invalid signatures.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: all existing and ported signature tests PASS.

```bash
git add src/jolt/crypto/dsa.clj src/jolt/crypto.clj test/jolt/crypto/dsa_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible digital signatures"
```

### Task 10: JWK and ECDSA Signature Transcoding

**Files:**
- Create: `src/jolt/crypto/keys/jwk/proto.clj`, `src/jolt/crypto/keys/jwk/rsa.clj`, `src/jolt/crypto/keys/jwk/ec.clj`, `src/jolt/crypto/keys/jwk/okp.clj`, `src/jolt/crypto/keys/jwk/eddsa.clj`
- Create: `src/jolt/crypto/util/ecdsa.clj`
- Create: `test/jolt/crypto/keys_jwk_test.clj`, `test/jolt/crypto/util/ecdsa_test.clj`
- Modify: `src/jolt/crypto/keys.clj`, `src/jolt/crypto.clj`, `test/jolt/crypto_test.clj`

**Interfaces:**
- Consumes: Tasks 1, 3, 8, and 9.
- Produces: JWK multimethods/converters, `keys/jwk`, `jwk->private-key`, `jwk->public-key`, `public-key->jwk`, `jwk-thumbprint`.
- Produces: raw integer/Base64URL helpers, `pkcs8-key`, `x509-key`, raw Ed key constructors, and `util.ecdsa/transcode-to-der`, `transcode-to-concat`.
- Supported curves: P-256, P-384, P-521, secp256k1, Ed25519, Ed448.

- [ ] **Step 1: Write failing JWK/transcoding tests**

Port every Buddy JWK and encoding test, including RFC RSA/EC/EdDSA signature vectors and thumbprints. Replace Bouncy Castle parameter construction and class assertions with raw bytes, Jolt key predicates, algorithms, encodings, and sign/verify. Add malformed DER, odd concatenated length, leading-zero coordinates, unsupported curves, and mismatched Ed private/public keys.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving JWK or ECDSA utility namespaces.

- [ ] **Step 3: Implement JWK conversions and transcoder**

Use exact unsigned big-endian integer encoding and hand-built canonical JSON strings in RFC 7638 field order. Construct/read OpenSSL keys from parameters without exposing native pointers; preserve curve coordinate widths and validate key pairs. Port DER transcoding rules and both original attributions.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: all RFC JWK/thumbprint/signature and transcoding vectors PASS.

```bash
git add src/jolt/crypto/keys.clj src/jolt/crypto/keys/jwk src/jolt/crypto/util/ecdsa.clj src/jolt/crypto.clj test/jolt/crypto/keys_jwk_test.clj test/jolt/crypto/util/ecdsa_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible JWK and ECDSA utilities"
```

### Task 11: Certificate Helpers

**Files:**
- Create: `src/jolt/crypto/certificates.clj`
- Create: `test/jolt/crypto/certificates_test.clj`
- Modify: `src/jolt/crypto.clj`, `src/jolt/crypto/internal/openssl.clj`, `test/jolt/crypto_test.clj`

**Interfaces:**
- Consumes: existing `CertificateFactory`/`X509Certificate` values and Task 8 public keys.
- Produces: `certificates/certificate`, `str->certificate`, `certificate?`, `subject`, `not-before`, `not-after`, `valid-on-date?`, `verify-signature`.

- [ ] **Step 1: Write failing certificate tests**

Port all Buddy certificate tests, replacing holder class assertions with `certificate?` and X.509 behavior. Retain exact subject, boundary dates, CA/signature truth values, and string input; add DER/path/reader inputs and malformed certificate/wrong key cases.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving `jolt.crypto.certificates`.

- [ ] **Step 3: Implement certificate API and signature verification**

Reuse the existing parsed certificate values for fields and identity. Bind OpenSSL X.509 signature verification for public keys and issuer certificates, returning booleans for valid/invalid signatures and throwing for malformed inputs.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: all certificate tests and existing X.509 tests PASS.

```bash
git add src/jolt/crypto/certificates.clj src/jolt/crypto.clj src/jolt/crypto/internal/openssl.clj test/jolt/crypto/certificates_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible certificate helpers"
```

### Task 12: DEFLATE Utility and Property Tests

**Files:**
- Create: `src/jolt/crypto/util/deflate.clj`
- Create: `test/jolt/crypto/util/deflate_test.clj`
- Modify: `deps.edn`, `test/jolt/crypto_test.clj`

**Interfaces:**
- Produces: `deflate/compress [input] [input {:nowrap boolean}]` and `uncompress [input] [input {:nowrap boolean :buffer-size int}]`.
- Test-only dependency: `org.clojure/test.check {:mvn/version "1.1.1"}` in the `:test` alias.

- [ ] **Step 1: Write failing DEFLATE properties**

Port all three 1000-case Buddy properties for raw, zlib-wrapped, and fallback decompression. Add deterministic empty, NUL-containing, large, repeated-byte, small-buffer, and malformed-input cases.

- [ ] **Step 2: Verify failure**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: FAIL resolving `jolt.crypto.util.deflate` or the test dependency.

- [ ] **Step 3: Implement DEFLATE and configure test.check**

Use the confirmed Jolt `Deflater`, `DeflaterOutputStream`, `Inflater`, and `InflaterInputStream` shims with Buddy's defaults and fallback. Add test.check only to the test alias and close streams/native compressor resources on every path.

- [ ] **Step 4: Verify and commit**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: 3000 property cases plus deterministic cases PASS.

```bash
git add deps.edn src/jolt/crypto/util/deflate.clj test/jolt/crypto/util/deflate_test.clj test/jolt/crypto_test.clj
git commit -m "feat: add Buddy-compatible DEFLATE utilities"
```

### Task 13: Documentation, Cold Verification, Review, and PR

**Files:**
- Modify: `README.md`, `CHANGELOG.md`
- Modify as needed: any source/test files flagged by diagnostics or review

**Interfaces:**
- Delivers the complete scoped API on `feat/buddy-core-openssl-port` with documentation of every supported namespace and deferred algorithm.

- [ ] **Step 1: Document the delivered compatibility surface**

Add namespace mapping and examples for hashing (including MD5 and SHA-256), MAC/KDF, authenticated encryption, signatures, PEM/JWK, certificates, and utilities. List exact deferrals and OpenSSL requirements. Add an Unreleased changelog entry and verify NOTICE/license coverage matches actual derived files.

- [ ] **Step 2: Cold-load every changed namespace**

Run a fresh `jolt -e` require for every source namespace added or modified, including test-alias cold loads for every ported test namespace.
Expected: no unresolved vars, missing classes, or load-time FFI failures.

- [ ] **Step 3: Run final tests and lint**

Run: `JOLT_PWD="$PWD" jolt -M:test`
Expected: all pre-existing and ported tests PASS with exit status 0.

Run the same jolt-lsp diagnostics used by `.github/workflows/lint.yml` and fix all error-level findings. Do not hide or exclude findings to make the gate pass.

- [ ] **Step 4: Review repository state and final diff**

Run `git status --short`, `git diff --check`, and review the complete branch diff against `main`. Confirm no caches, logs, `.clj-kondo`, `.lsp`, generated natives, or unrelated changes are included, and no deferred algorithm has a placeholder implementation.

- [ ] **Step 5: Commit documentation, push, and open the PR**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: describe Buddy-compatible crypto APIs"
git push -u origin feat/buddy-core-openssl-port
gh pr create --title "Add Buddy-compatible OpenSSL crypto APIs" --body "Ports the OpenSSL-supported Buddy Core API surface and tests under jolt.crypto. Includes Apache 2.0 attribution, supported-algorithm documentation, and explicit deferrals for algorithms OpenSSL cannot supply. Verification: JOLT_PWD=\"$PWD\" jolt -M:test and jolt-lsp diagnostics."
```

Expected: PR URL returned; report it with test evidence and deferred algorithm summary.
