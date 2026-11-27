# Buddy-compatible OpenSSL API port

## Intent

Port the useful Buddy Core API surface to Jolt under `jolt.crypto`, preserving
Buddy's function names, option maps, protocols, engine lifecycle, byte-oriented
results, and known-answer behavior. Port Buddy's tests alongside the
implementation so compatibility is demonstrated rather than inferred.

This PR covers algorithms supplied by the supported OpenSSL 3 default provider,
plus format conversions and cryptographic constructions built from those
primitives. Algorithms OpenSSL cannot supply faithfully are deliberately left
for later work; there will be no placeholders, truncated-output substitutes, or
silent fallback to a different algorithm.

The existing `jolt.crypto` host-class shims and `jolt.crypto.x509` API must keep
working unchanged.

## Goals

- Mirror Buddy's namespaces below the `jolt.crypto` root:
  - `buddy.core.*` becomes `jolt.crypto.*` (for example,
    `buddy.core.hash` -> `jolt.crypto.hash`).
  - `buddy.util.*` becomes `jolt.crypto.util.*`.
- Preserve public function and protocol names, arities, defaults, aliases,
  option keywords, streaming behavior, and mutable engine operations wherever
  the corresponding algorithm is in scope.
- Reuse the repository's OpenSSL FFI and Jolt key/certificate values. Do not add
  Bouncy Castle, JVM dependencies, reflection, or another crypto runtime.
- Port Buddy's tests and fixtures, retaining expected vectors and assertions
  except where a JVM/Bouncy Castle concrete type assertion must become a Jolt
  behavioral assertion.
- Include Apache 2.0 attribution and license notices for Buddy-derived source,
  tests, fixtures, and the Nimbus-derived ECDSA transcoder.
- Finish on a feature branch with a GitHub PR after all checks pass.

## Non-goals and deferred algorithms

This PR does not implement algorithms absent from OpenSSL 3's default provider,
even if Bouncy Castle supports them. Specifically defer:

- Tiger, Whirlpool, RIPEMD-128/256/320, BLAKE3, and Skein.
- BLAKE2b-128 and BLAKE2b-256. OpenSSL's BLAKE2b-512 output cannot be truncated
  to implement these differently parameterized hash functions.
- Twofish and Serpent, including their block-cipher and Poly1305 variants.
- Any other algorithm that cannot be reproduced exactly by the supported
  OpenSSL providers on all target platforms.

Algorithm-specific vars for deferred hashes are omitted. Generic engine maps do
not contain deferred algorithms, and constructors reject them clearly. Generic
`blake2b` accepts only its supported 64-byte output length. These are explicit
unsupported-algorithm errors, not stub implementations.

No `buddy.*` compatibility namespaces, Java class emulation, KeyStore/TLS API,
or high-level JWT/JWE API is added.

## Constraints

- Jolt compiles Clojure to Chez Scheme; only its existing host shims and
  `jolt.ffi` are available for native interop.
- OpenSSL calls must use exported functions available in OpenSSL 3 and free all
  native allocations and contexts on success and failure.
- Standard provider behavior is required. Whirlpool is excluded because it is
  legacy-provider-only in OpenSSL 3; RIPEMD-160 is included because it is in the
  default provider.
- Keys and certificates remain Jolt tagged-table host values with
  `getEncoded`/`getAlgorithm` behavior, not Bouncy Castle objects.
- Engine objects will be Jolt records or equivalent values implementing Buddy's
  protocols, with mutable native or accumulated state hidden behind the same
  lifecycle. Bouncy Castle engine parameter objects are replaced by Jolt maps,
  byte arrays, and key values at this implementation boundary.
- No algorithm with security-relevant behavioral differences may be accepted
  merely because its family name matches. For example, ChaCha is included only
  if Buddy's original 64-bit-nonce stream behavior passes Buddy's vectors.
- The current untracked `.clj-kondo/` and `.lsp/` directories are user state and
  must not be added to the branch.

## Approaches considered

1. **OpenSSL-backed compatibility layer (selected).** Reuse and extend the
   current FFI for standard primitives; implement codecs, padding, KDF
   constructions, JWK canonicalization, ECDSA transcoding, and similar glue in
   Clojure. This keeps the repository's deployment model and limits new work to
   the compatibility layer and missing OpenSSL bindings.
2. **Pure Jolt implementations for the entire Buddy API.** Rejected for this PR
   because it would require new implementations of every niche algorithm and
   would replace already verified OpenSSL primitives.
3. **An additional native crypto library.** Rejected because no single portable
   dependency covers the original full Buddy algorithm set, while it would add
   native loading and packaging complexity.

The user initially requested full parity, then explicitly narrowed this PR to
OpenSSL-supplied algorithms. The selected approach follows that revised scope.

## API and implementation design

### Shared foundation

Add internal shared helpers for byte-array coercion/copying, unsigned integer
and DER encoding, stream digestion, OpenSSL error handling, and native resource
ownership where reuse avoids duplicate FFI lifecycle code. Extend the existing
`jolt.crypto` bindings only where needed for additional digests, cipher modes,
RSA-PSS, Ed448, key parameters, PEM decryption, key wrapping, and certificate
verification. Keep these implementation details out of the public Buddy-style
API.

Digest, MAC, cipher, KDF, and signature engines implement Buddy's public
protocols using Jolt types. Constructors accept the same keywords and factory
functions. Low-level `reset!`, `update!`, `end!`, `init!`, `process-block!`,
`process-bytes!`, sizing, and finalization calls preserve state across calls and
honor input/output offsets and lengths.

### Namespaces and supported behavior

- `jolt.crypto.bytes`, `jolt.crypto.codecs`, and
  `jolt.crypto.codecs.base64`: byte predicates, fill/slice/copy/concat,
  constant-time equality, UTF encodings, hex, standard and URL-safe Base64,
  signed 64-bit conversion, coercions, deprecated aliases, and metadata.
- `jolt.crypto.padding` and `jolt.crypto.nonce`: PKCS#7, TBC, and zero-byte
  padding; secure random bytes/nonces; nonce selection by engine block size.
- `jolt.crypto.hash`: MD5, SHA-1, SHA-256/384/512, SHA3-256/384/512,
  BLAKE2b-512, and RIPEMD-160; generic digest engines and byte, string, stream,
  file, URL, and URI inputs.
- `jolt.crypto.mac`: HMAC over supported digest engines, AES-based Poly1305,
  constant-time verification, and the same input types as hashes. Generic HMAC
  and KDF code may use every supported digest, not only digest variants named
  in Buddy's own tests.
- `jolt.crypto.kdf`: HKDF, KDF1, KDF2, counter-mode KDF, feedback-mode KDF,
  double-pipeline-iteration KDF, and PBKDF2 over supported digests, including
  defaults and `ByteBuffer` results.
- `jolt.crypto.crypto`: AES in ECB, CBC, CTR/SIC, OFB, and GCM modes; original
  ChaCha streaming behavior; low-level engines; AES-CBC-HMAC-SHA2 and AES-GCM
  high-level encryption/decryption with AAD and authentication failures.
- `jolt.crypto.dsa`: RSA PKCS#1 v1.5 and RSA-PSS with SHA-256/384/512, ECDSA with
  SHA-256/384/512, and EdDSA for Ed25519 and Ed448 over all Buddy input types.
- `jolt.crypto.keys` and `jolt.crypto.keys.pem`: encrypted and unencrypted PEM
  private keys, public keys and certificates, string/path/reader inputs, RSA,
  DSA, EC, Ed25519 and Ed448 key predicates, and AES key wrap/unwrap.
- `jolt.crypto.keys.jwk.proto`, `.rsa`, `.ec`, `.okp`, and `.eddsa`: RSA and EC
  JWK conversion, P-256/P-384/P-521/secp256k1 curves, Ed25519/Ed448 OKP
  conversion, public/private consistency checks, RFC 7638 canonical thumbprints,
  and raw-key/PKCS#8/SPKI extraction helpers. Preserve public Buddy var names;
  raw byte arrays replace Bouncy Castle parameter objects where necessary.
  OpenSSL key constructors/accessors handle parameters without exposing native
  pointers in public values.
- `jolt.crypto.certificates`: PEM/path/reader/string certificate parsing,
  subject and validity accessors, validity predicates, certificate predicates,
  and signature verification with either a public key or issuer certificate.
- `jolt.crypto.util.ecdsa`: DER <-> concatenated ECDSA signature transcoding,
  retaining the Nimbus attribution as well as Buddy's.
- `jolt.crypto.util.deflate`: raw DEFLATE and zlib-wrapped compression,
  decompression, buffer-size options, and raw-to-zlib fallback using Jolt's
  confirmed `java.util.zip` shims.

### Tests and fixtures

Port each Buddy test namespace to the corresponding `jolt.crypto.*-test`
namespace and register all of them with the existing `jolt -M:test` entry point.
The original custom shim and X.509 checks continue to run; ported tests use
`clojure.test`, and the process exits nonzero for either suite's failures.

Copy Buddy's `test/_files` fixtures unchanged into the same relative test
location so paths, stream digests, encrypted PEM behavior, certificates, and
key vectors remain comparable. Preserve known-answer vectors, iteration counts,
round trips, negative verification, malformed input, and streaming cases.

Only remove tests tied to the deferred algorithms above. Adapt tests that name
Bouncy Castle classes to assert Jolt-observable behavior instead: key algorithm,
key predicate, encoding, sign/verify, or round-trip equality. Replace direct
Bouncy Castle engine construction with the public Jolt engine constructor. Keep
Buddy's helper-level tests for raw key extraction and ECDSA transcoding.

Add `org.clojure/test.check` to the test alias for the three 1000-case DEFLATE
properties. Add focused Jolt-only tests where the OpenSSL compatibility boundary
needs coverage absent from Buddy, especially exact algorithm rejection, native
resource cleanup, offsets, and authentication failure behavior.

### Documentation and attribution

- Add a `NOTICE` identifying Buddy Core, its authors, the source repository, and
  the exact source revision (`9763a3f` in the supplied checkout), plus Nimbus
  ECDSA attribution.
- Include the Apache License 2.0 text for the derived works and retain original
  per-file copyright/license headers with prominent modification notices.
- Document the namespace mapping, examples, supported algorithms, explicit
  deferrals, and attribution in the README. Add an Unreleased changelog entry.
- Commit this design on `feat/buddy-core-openssl-port`; implementation and test
  commits follow design approval.

## Verification and delivery

1. Port tests with their implementation in small, runnable namespace groups.
2. Exercise stateful engines through real public calls, not only cold compilation.
3. Run every changed namespace in a fresh Jolt process to catch session drift.
4. Run `JOLT_PWD="$PWD" jolt -M:test`, matching CI, with all pre-existing and
   ported tests passing.
5. Run the repository's jolt-lsp diagnostics and resolve error-level findings.
6. Review the diff for accidental fixtures, caches, generated output, native
   leaks, unsupported stubs, and missing attribution.
7. Commit the completed work on `feat/buddy-core-openssl-port`, push it to
   `origin`, and open a PR summarizing support, deferrals, attribution, and test
   evidence.

## Builder discretion

The builder may choose the precise internal record layout and factor shared FFI
helpers to fit the existing code. OpenSSL function selection may change during
implementation as long as exact behavior is established by the ported vectors.
Test-only helper names and internal file organization are also discretionary.
Public scope, supported algorithm behavior, test expectations, licensing, and
the requirement not to regress existing APIs are not discretionary.
