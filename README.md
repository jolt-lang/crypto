# jolt-crypto

Crypto for [Jolt](https://github.com/jolt-lang/jolt), bound to the system
OpenSSL (`libcrypto`) through `jolt.ffi`, and exposed as the slice of the
`javax.crypto` / `java.security` surface real Clojure libraries touch:

| Class | What you get |
|-------|--------------|
| `javax.crypto.Cipher` | `AES/CBC/PKCS5Padding` (128/192/256 — key length picks the variant) |
| `javax.crypto.Mac` | `HmacSHA512`, `HmacSHA384`, `HmacSHA256`, `HmacSHA1` |
| `java.security.MessageDigest` | `SHA-512`, `SHA-384`, `SHA-256`, `SHA-224`, `SHA-1`, `MD5` |
| `java.security.SecureRandom` | `RAND_bytes`-backed `nextBytes` / `generateSeed` / `nextInt` / `nextLong` / `nextDouble` / `nextFloat` / `nextBoolean` |
| `javax.crypto.spec.SecretKeySpec` / `IvParameterSpec` | key + IV holders |
| `java.security.KeyPairGenerator` | EC keygen over P-256 / P-384 / P-521 / secp256k1, RSA keygen (512–16384 bits, default 2048, exponent 65537), and Ed25519 (`Ed25519` / `EdDSA`) |
| `java.security.Signature` | `SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512withECDSA`, `…withRSA`, and `Ed25519` / `EdDSA` |
| `java.security.KeyFactory` | EC, RSA and Ed25519 keys from encoded DER |
| `java.security.spec.ECGenParameterSpec` / `X509EncodedKeySpec` / `PKCS8EncodedKeySpec` | curve name + DER key holders |
| `java.security.cert.CertificateFactory` | `X.509` certificates from PEM (one or a bundle) or DER, via `generateCertificate` / `generateCertificates` |
| `java.security.cert.X509Certificate` | subject / issuer (`X500Principal` and `getSubjectDN`), `getNotBefore` / `getNotAfter` / `checkValidity`, serial, version, `getSigAlgName` / `getSigAlgOID`, `getPublicKey`, `getEncoded` |

This is enough for `ring-core`'s encrypted session-cookie store and the CSRF
token machinery, so **ring-defaults** loads and runs on Jolt, and for
`nrepl/nrepl`'s TLS namespace to load, so nREPL middleware libraries do.

A certificate is parsed once and kept as data: what `X509Certificate` answers
is what the JDK's does for the same bytes — RFC 2253 names from
`getSubjectX500Principal`, the RFC 1779 spelling from `getSubjectDN`, the JDK's
signature-algorithm names (`SHA256withECDSA`), and the same DER from
`getEncoded`. What is not here: chain validation, `KeyStore`, `SSLContext`
and the rest of TLS.

The EC keys and signatures are wire-compatible with the JVM in both directions.
`getEncoded` gives the same X.509 SubjectPublicKeyInfo and PKCS#8 PrivateKeyInfo
DER the JDK does, and `Signature` produces the DER-encoded `SEQUENCE` of *r* and
*s* that `SHA256withECDSA` produces there, so keys and signatures cross between a
JVM and a Jolt process unchanged. Two small supersets: the curve aliases
`prime256v1` and `P-256` are accepted alongside the JDK's `secp256r1` and
`NIST P-256`, and `secp256k1` is available where the default JDK provider has no
such curve. OpenSSL's PKCS#8 embeds the optional public key where the JDK's does
not, so a private key encodes to 138 bytes rather than the JDK's 67; both forms
parse on either side.

RSA is the same story: `SHA256withRSA` and friends produce the PKCS#1 v1.5
signature the JDK does (a 256-byte ciphertext for a 2048-bit key), and
`KeyFactory` reads the SPKI/PKCS#8 DER a JVM writes. `KeyPairGenerator` accepts
the JDK's 512–16384 bit range and defaults to 2048 like a modern JDK. OpenSSL
takes the primitive from the key rather than from the algorithm name, so
`Signature` and `KeyFactory` check the two agree and reject a key of the other
algorithm the way the JDK does, rather than quietly signing with whichever key
they were handed.

Ed25519 follows the JDK's EdDSA provider (Java 15 and later): `Ed25519` and
`EdDSA` both name it in `Signature`, `KeyFactory` and `KeyPairGenerator`, keys
report `getAlgorithm` as `EdDSA`, and `getEncoded` gives the X.509 and PKCS#8
DER a JVM writes. Signatures are the 64-byte RFC 8032 form, byte for byte what
the RFC's test vectors give. `initialize` takes 255, Ed25519's one size.

## Use

```clojure
;; deps.edn
jolt-lang/jolt-crypto {:git/url "https://github.com/jolt-lang/crypto"
                       :git/sha "..."}
```

Each release is a git tag. [CHANGELOG.md](CHANGELOG.md) lists what changed in
each one.

```clojure
(require 'jolt.crypto)   ;; installs the host-class shims on load
```

The shims register through Jolt's host-shim hooks (`__register-class-ctor!` /
`__register-class-statics!` / `__register-class-methods!`) — the same seam
[jolt-lang/http-client](https://github.com/jolt-lang/http-client) uses for its
`java.net` / `java.io` shims. `libcrypto`/`libssl` are declared `:jolt/native`
and loaded before the namespace; an app that also pulls http-client shares the
one loaded copy (jolt.deps reconciles natives).

## Buddy-compatible API

The OpenSSL-backed port maps `buddy.core.*` namespaces to `jolt.crypto.*` and
`buddy.util.*` to `jolt.crypto.util.*`. Public functions, protocols, option
maps, and byte-array results retain their Buddy names and arities. The existing
`jolt.crypto` host-class shims and `jolt.crypto.x509` certificate builder remain
available alongside these namespaces.

| Buddy namespace | Jolt namespace | Delivered surface |
|-----------------|----------------|-------------------|
| `buddy.core.bytes` | `jolt.crypto.bytes` | Byte predicates, ranged fill, slice/copy/concat, constant-time equality |
| `buddy.core.codecs` | `jolt.crypto.codecs` | Byte coercions, UTF strings, hex, Base64/Base64URL, signed 64-bit conversion |
| `buddy.core.codecs.base64` | `jolt.crypto.codecs.base64` | Byte-array Base64 encoder/decoder, standard and URL-safe |
| `buddy.core.hash` | `jolt.crypto.hash` | One-shot and stateful digest engines |
| `buddy.core.mac` | `jolt.crypto.mac` | HMAC, AES-Poly1305, constant-time verification |
| `buddy.core.kdf` | `jolt.crypto.kdf` | HKDF, KDF1/KDF2, counter/feedback/double-pipeline KDF, PBKDF2 |
| `buddy.core.crypto` | `jolt.crypto.crypto` | Stateful cipher engines and high-level authenticated encryption |
| `buddy.core.dsa` | `jolt.crypto.dsa` | RSA, ECDSA, and EdDSA signing and verification |
| `buddy.core.keys` | `jolt.crypto.keys` | PEM/key constructors, JWK facade, key predicates, AES key wrap |
| `buddy.core.keys.pem` | `jolt.crypto.keys.pem` | Private/public PEM readers |
| `buddy.core.keys.jwk.*` | `jolt.crypto.keys.jwk.*` | RSA, EC, OKP, and EdDSA conversion plus RFC 7638 thumbprints |
| `buddy.core.certificates` | `jolt.crypto.certificates` | X.509 parsing, fields, validity, signature verification |
| `buddy.core.padding` | `jolt.crypto.padding` | PKCS#7, TBC, and zero-byte padding |
| `buddy.core.nonce` | `jolt.crypto.nonce` | Secure random bytes/nonces and engine-sized IVs |
| `buddy.util.ecdsa` | `jolt.crypto.util.ecdsa` | DER ↔ concatenated ECDSA signature transcoding |
| `buddy.util.deflate` | `jolt.crypto.util.deflate` | Raw DEFLATE and zlib-wrapped compression |

### Hashing

```clojure
(require '[jolt.crypto.codecs :as codecs]
         '[jolt.crypto.hash :as hash])

(codecs/bytes->hex (hash/md5 "abc"))
;; => "900150983cd24fb0d6963f7d28e17f72"

(codecs/bytes->hex (hash/sha256 "abc"))
;; => "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

(let [engine (hash/resolve-digest-engine :sha256)]
  (hash/update! engine (codecs/str->bytes "a"))
  (hash/update! engine (codecs/str->bytes "bc"))
  (codecs/bytes->hex (hash/end! engine)))
;; => the same SHA-256 digest; end! resets the engine for reuse
```

Digests accept byte arrays, strings, streams, files, URLs, and URIs. Supported
algorithms are `:md5`, `:sha1`, `:sha256`, `:sha384`, `:sha512`, `:sha3-256`,
`:sha3-384`, `:sha3-512`, `:blake2b-512`, and `:ripemd160`. Named functions are
available for each. `:ripemd160` needs OpenSSL 3.0.7 or later: earlier 3.0
releases (Ubuntu 22.04 ships 3.0.2) keep it in the legacy provider, which this
library does not load, so there it throws an unsupported-algorithm `ex-info`.
`(jolt.crypto.internal.openssl/digest-available? :ripemd160)` reports which. Generic `blake2b` accepts only a 64-byte output length;
BLAKE2b output is never truncated to imitate another algorithm.

### MAC and key derivation

```clojure
(require '[jolt.crypto.kdf :as kdf]
         '[jolt.crypto.mac :as mac])

(let [options {:key "secret" :alg :hmac+sha256}
      tag (mac/hash "message" options)]
  (mac/verify "message" tag options))
;; => true

(-> (kdf/engine {:alg :pbkdf2+sha256
                 :key "password" :salt "salt" :iterations 100000})
    (kdf/get-bytes 32)
    codecs/bytes->hex)
;; => a 64-character hex string
```

Generic `:hmac` defaults to SHA-256 and accepts every supported digest through
`:digest`; shorthand engines are `:hmac+sha1`, `:hmac+sha256`, `:hmac+sha384`,
and `:hmac+sha512`. `:poly1305+aes`, or `:poly1305` with `{:cipher :aes}`,
implements Buddy's AES-based Poly1305 construction with a 32-byte key and
16-byte IV. It is not a substitute for ChaCha20-Poly1305 or raw-key Poly1305.

KDF constructions are `:hkdf`, `:kdf1`, `:kdf2`, `:cmkdf` (counter mode),
`:fmkdf` (feedback mode), `:dpimkdf` (double-pipeline iteration), and `:pbkdf2`.
Their generic forms accept the supported digest keywords; PBKDF2 defaults to
`kdf/+pbkdf2-iterations+` (1000) when `:iterations` is omitted. `get-bytes`
returns a byte array and `get-buffer` returns a `ByteBuffer` over the derived
bytes. HKDF, KDF1, KDF2, CMKDF, FMKDF, and DPIMKDF have `+sha256`, `+sha384`,
`+sha512`, and `+blake2b-512` aliases; PBKDF2 has `+sha256`, `+sha384`, and
`+sha512` aliases. Buddy's misspelled `+sha386` aliases also resolve to
SHA-384 (in Buddy they always threw). The generic form is the complete digest interface.

### Authenticated encryption and stateful ciphers

```clojure
(require '[jolt.crypto.crypto :as crypto]
         '[jolt.crypto.nonce :as nonce])

(let [key (nonce/random-bytes 32)
      iv (nonce/random-bytes 12)
      options {:alg :aes256-gcm :aad "request-42"}
      ciphertext (crypto/encrypt (codecs/str->bytes "secret") key iv options)]
  (codecs/bytes->str (crypto/decrypt ciphertext key iv options)))
;; => "secret"
```

High-level schemes are `:aes128-cbc-hmac-sha256`,
`:aes192-cbc-hmac-sha384`, `:aes256-cbc-hmac-sha512`, `:aes128-gcm`,
`:aes192-gcm`, and `:aes256-gcm`. The default is
`:aes128-cbc-hmac-sha256`. CBC-HMAC uses Buddy's key splitting and truncated
HMAC tags; GCM uses a 128-bit authentication tag. Decryption authenticates
before returning plaintext and rejects modified ciphertext, IV, AAD, or tags.

Low-level engines support AES with 16/24/32-byte keys in `:ecb`, `:cbc`,
`:ctr`/`:sic`, `:ofb`, and `:gcm` modes, plus `:chacha` with Buddy's original
64-bit-nonce stream behavior. `block-cipher`, `stream-cipher`, `init!` (alias
`initialize!`), `process-block!`, `process-bytes!`, and `end!` expose the
stateful API.

**Native engine lifecycle:** an initialized low-level cipher owns a native
OpenSSL context. Always call `end!` after processing, including on error paths,
and call `init!`/`initialize!` again before reuse. Reinitialization releases the
previous context, but these engines have **no GC finalizer**: abandoning an
active engine without `end!` or reinitialization leaks that context. The
high-level `encrypt`/`decrypt` helpers finalize their own engines.

### Digital signatures

```clojure
(require '[jolt.crypto.dsa :as dsa]
         '[jolt.crypto.keys :as keys])

(let [private (keys/private-key "test/_files/privkey.ecdsa.pem" "secret")
      public (keys/public-key "test/_files/pubkey.ecdsa.pem")
      signature (dsa/sign "message" {:alg :ecdsa+sha256 :key private})]
  (dsa/verify "message" signature {:alg :ecdsa+sha256 :key public}))
;; => true
```

Supported `:alg` values are `:rsassa-pkcs15+sha256`,
`:rsassa-pkcs15+sha384`, and `:rsassa-pkcs15+sha512` for RSA PKCS#1 v1.5;
`:rsassa-pss+sha256`, `:rsassa-pss+sha384`, and `:rsassa-pss+sha512` for
RSA-PSS; `:ecdsa+sha256`, `:ecdsa+sha384`, and `:ecdsa+sha512` for ECDSA; and
`:eddsa` for Ed25519 and Ed448. RSA-PSS uses the matching digest for MGF1.
Inputs have the same byte, string, stream, file, URL, and URI forms as hashes.

For API compatibility, `dsa/sign` accepts a `:prng` option but **ignores it**:
OpenSSL supplies the randomness for randomized signature algorithms. This does
not weaken OpenSSL's secure random generation, but a caller-supplied PRNG cannot
be used to force deterministic ECDSA or RSA-PSS output.

### PEM, JWK, and key wrapping

```clojure
(let [private (keys/private-key "test/_files/privkey.ed25519.pem")
      public (keys/public-key "test/_files/pubkey.ed25519.pem")
      jwk (keys/jwk private public)]
  {:curve (:crv jwk)
   :thumbprint (codecs/bytes->b64-str (keys/jwk-thumbprint jwk) true)
   :round-trips? (= jwk (keys/jwk (keys/jwk->private-key jwk)
                                  (keys/jwk->public-key jwk)))})
;; => {:curve "Ed25519" :thumbprint "..." :round-trips? true}
```

PEM readers accept paths, strings/readers through the facade, encrypted and
unencrypted traditional keys, and PKCS#8. Supported key types are RSA, DSA, EC,
Ed25519, and Ed448; public keys can also be extracted from certificates.
`keys/wrap` and `keys/unwrap` implement RFC 3394 AES key wrapping with
16/24/32-byte key-encryption keys.

JWK conversion covers RSA, EC P-256/P-384/P-521/secp256k1, and OKP
Ed25519/Ed448, including public/private consistency checks and canonical
SHA-256 RFC 7638 thumbprints. Raw Ed key, PKCS#8, and SPKI helpers are in
`jolt.crypto.keys.jwk.eddsa`; unsigned integer helpers and JWK multimethods are
in `jolt.crypto.keys.jwk.proto`.

**Bounded RSA recovery:** OpenSSL 3 requires CRT parameters for operations on
an RSA private key. For an n/e/d-only private JWK, the port tries at most 100
candidate bases while recovering the factors and CRT values, then validates the
key. This bounded, fail-closed recovery can reject an exotic but valid key.
Private JWKs that already supply the complete CRT fields (`p`, `q`, `dp`, `dq`,
and `qi`) are validated directly and bypass recovery. `keys/jwk` writes the CRT
fields for every RSA private key except one read from an n/e/d-only JWK, which
it writes back as n/e/d.

### Certificates

```clojure
(require '[jolt.crypto.certificates :as certificates])

(let [cert (certificates/certificate "test/_files/cert.rsa.pem")
      issuer (certificates/certificate "test/_files/ca-cert.rsa.pem")]
  {:subject (certificates/subject cert)
   :valid-now? (certificates/valid-on-date? cert)
   :signed-by-issuer? (certificates/verify-signature cert issuer)})
```

`certificate` reads PEM or DER from paths, byte arrays, and streams, and PEM
from readers; `str->certificate` reads a PEM string. The namespace also exposes
`certificate?`, `subject`, `not-before`, `not-after`, `valid-on-date?`, and
`verify-signature` with either a public key or an issuer certificate. Signature
verification checks only the certificate signature, not chain trust, revocation,
hostnames, or validity constraints. The `jolt.crypto.x509` builder documented
below is unchanged.

### Utilities

- `jolt.crypto.bytes` and `jolt.crypto.codecs` provide byte manipulation,
  constant-time equality, strict hex/Base64 decoding, standard and unpadded
  URL-safe Base64, UTF conversion, and signed 64-bit big-endian conversion.
- `jolt.crypto.padding` provides `:pkcs7`, `:tbc`, and `:zerobyte` engines;
  `jolt.crypto.nonce` provides CSPRNG bytes, timestamp-plus-random nonces, and
  engine-appropriate IVs.
- `jolt.crypto.util.ecdsa/transcode-to-der` converts a fixed-width JWS R+S
  signature to DER; `transcode-to-concat` converts DER back with the requested
  total output width (64 bytes for P-256, 96 for P-384, 132 for P-521).
- `jolt.crypto.util.deflate/compress` defaults to raw DEFLATE (`:nowrap true`),
  while `{:nowrap false}` selects zlib wrapping. `uncompress` defaults to raw
  input, accepts `:buffer-size`, and retries as zlib after raw decompression
  fails with `ZipException`.

### Deferred algorithms and scope

There are no placeholders, truncated-output substitutes, or fallbacks to a
different cipher. Unsupported constructors throw explicit errors. The following
are deferred because the supported OpenSSL 3 providers cannot reproduce them
faithfully on all target platforms:

- Tiger, Whirlpool, RIPEMD-128, RIPEMD-256, RIPEMD-320, BLAKE3, and Skein.
- BLAKE2b-128 and BLAKE2b-256, which are distinct parameterizations rather than
  truncated BLAKE2b-512.
- Twofish and Serpent, including their block-cipher and Poly1305 variants.
- Any other algorithm without exact, portable OpenSSL 3 provider support.

Algorithm-specific vars for deferred hashes are omitted, and generic engine
maps reject them. This port does not add `buddy.*` aliases, Bouncy Castle or JVM
dependencies, `KeyStore`/TLS APIs, or high-level JWT/JWE APIs.

### Attribution

Buddy-derived source, tests, and fixtures retain their copyright and Apache
License 2.0 notices, with prominent Jolt modification notices. [NOTICE](NOTICE)
records Buddy Core, Andrey Antukh, the source repository and revision
`9763a3f`; [LICENSE-buddy-core](LICENSE-buddy-core) contains the applicable
Apache License 2.0 text. The ECDSA transcoder also retains its Nimbus JOSE +
JWT / Connect2id attribution in `NOTICE` and `jolt.crypto.util.ecdsa`.

## Making certificates

The JDK has no public API for creating a certificate. A JVM program shells out
to `keytool` or pulls in Bouncy Castle, so there is no class to imitate here.
`jolt.crypto.x509` is a small function API instead: an options map goes in, and
out comes the same `X509Certificate` value `CertificateFactory` returns.

```clojure
(require '[jolt.crypto.x509 :as x509])

;; a self-signed localhost certificate and its key, for a test or dev TLS server
(let [{:keys [certificate private-key]}
      (x509/generate {:subject "CN=localhost"
                      :san [[:dns "localhost"] [:ip "127.0.0.1"] [:ip "::1"]]})]
  (spit "cert.pem" (x509/pem certificate))
  (spit "key.pem" (x509/pem private-key)))   ; PKCS#8 "PRIVATE KEY"

;; a small CA and a client certificate it issues, for mTLS tests
(let [{ca :certificate ca-key :private-key} (x509/generate {:subject "CN=Test CA" :ca? true})
      {client :certificate client-key :private-key}
      (x509/generate {:subject "CN=client"
                      :issuer ca :signing-key ca-key
                      :extended-key-usage #{:client-auth}})]
  ...)
```

`(x509/certificate opts)` signs a certificate for a public key you already
have, and `(x509/generate opts)` makes the key pair too, answering
`{:certificate :private-key}`. `(x509/pem x)` writes a certificate, a private
key (PKCS#8) or a public key (SubjectPublicKeyInfo) as PEM text.

| Option | Meaning |
|--------|---------|
| `:subject` | RFC 2253 name, the `X500Principal` form: `"CN=localhost,O=Example"`. Required |
| `:public-key` | the subject's `PublicKey`. Required by `certificate`; `generate` makes it |
| `:signing-key` | the `PrivateKey` that signs: the subject's own when self-signed, the CA's otherwise. `generate` defaults it to the new key when there is no `:issuer` |
| `:issuer` | the CA's `X509Certificate`. Absent means self-signed |
| `:san` | `[[:dns "localhost"] [:ip "127.0.0.1"] [:ip "::1"]]`: DNS names, IPv4 and IPv6 addresses |
| `:days` | validity counted from `:not-before`, default 365 |
| `:not-before` / `:not-after` | `java.util.Date` or `#inst`. `:not-before` defaults to now, `:not-after` replaces `:days` |
| `:serial` | a positive integer below 2^159; the default is 159 random bits |
| `:ca?` | `true` makes a CA: critical `basicConstraints CA:TRUE`, and keyUsage keyCertSign, cRLSign and digitalSignature unless `:key-usage` is given |
| `:key-usage` | `#{:digital-signature :non-repudiation :key-encipherment :data-encipherment :key-agreement :key-cert-sign :crl-sign :encipher-only :decipher-only}`, marked critical |
| `:extended-key-usage` | `#{:server-auth :client-auth :code-signing :email-protection :time-stamping :ocsp-signing}` |
| `:key-type` | `generate` only: `:ec` (P-256, the default), `:rsa` (2048 bits) or `:ed25519` |
| `:key-size` | `generate` only: RSA modulus bits, or 256, 384 or 521 to pick the EC curve. Not for `:ed25519`, which has one size |

Every certificate is version 3, and the signing key decides the signature
algorithm: `SHA256withRSA`, `SHA256withECDSA` or `Ed25519`. Each one carries a
subjectKeyIdentifier and a basicConstraints extension (`CA:FALSE` on a leaf).
An issued certificate also carries the authorityKeyIdentifier that points back
at its CA. A leaf gets no keyUsage or extendedKeyUsage unless you ask, because
an absent extension restricts nothing, and the JDK's TLS client and OpenSSL
both accept those defaults for a localhost server. Bad input throws an
`ex-info` that names the problem, whether it is a misspelt option, an unknown
SAN kind, an address that does not parse, a malformed name, or a signing key
that belongs to neither the issuer nor, when self-signed, `:public-key`.
A CA whose `:key-usage` leaves out `:key-cert-sign` is refused too, since it
could not issue anything.

Some things are deliberately left out. Names take the `X500Principal` text
form with `\,` and `\XX` escapes (the bytes must be UTF-8) and an `OID.`
prefix, but not quoted values, multi-valued RDNs (`CN=a+O=b`) or the `#hex`
BER form. An EC key signs with SHA-256 whatever its curve. There is no
pathLenConstraint, and an issued certificate's validity is not checked against
its CA's, so a leaf can outlive the CA that signed it.

## OpenSSL

The library needs OpenSSL 3 at runtime; OpenSSL 1.1 is no longer supported. The compatibility layer targets
OpenSSL 3's default provider and does not require or enable the legacy provider.
The native libraries are looked for in:

- **macOS:** Homebrew (`/opt/homebrew/opt/openssl@3/lib`, `/usr/local/opt/openssl@3/lib`),
  MacPorts (`/opt/local/lib`), then `libcrypto.3.dylib` / `libssl.3.dylib` on the
  dynamic loader's path. Never `/usr/lib/libcrypto.dylib`: that is Apple's stub,
  and opening it aborts the process.
- **Linux:** `libcrypto.so.3`, `libcrypto.so` (and the `libssl` equivalents).
- **Windows:** `libcrypto-3-x64.dll` and the other names OpenSSL's builds ship, beside
  the executable or on `PATH`.

The libraries are declared `:optional`. jolt loads every dependency's natives when
the program starts, whether or not anything uses them, so an app that only has this
library somewhere in its dependency tree still starts on a host without OpenSSL. A
call into it then fails at the call, naming the OpenSSL function it could not find.

To link OpenSSL into a `jolt build` binary instead, add the static archives
in your app's `deps.edn`. jolt links the system libraries `libcrypto.a` needs
itself; on Windows that takes jolt 0.8.16 or later, which added `crypt32`:

```clojure
:jolt/native [{:name "crypto" :static {:archive "/mingw64/lib/libcrypto.a"}}
              {:name "ssl"    :static {:archive "/mingw64/lib/libssl.a"}}]
```

## Test

```
jolt -M:test
```
