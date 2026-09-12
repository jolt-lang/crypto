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
| `java.security.KeyPairGenerator` | EC keygen over P-256 / P-384 / P-521 / secp256k1 |
| `java.security.Signature` | `SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512withECDSA` |
| `java.security.KeyFactory` | EC keys from encoded DER |
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

## Use

```clojure
;; deps.edn
jolt-lang/jolt-crypto {:git/url "https://github.com/jolt-lang/jolt-crypto"
                       :git/sha "..."}
```

```clojure
(require 'jolt.crypto)   ;; installs the host-class shims on load
```

The shims register through Jolt's host-shim hooks (`__register-class-ctor!` /
`__register-class-statics!` / `__register-class-methods!`) — the same seam
[jolt-lang/http-client](https://github.com/jolt-lang/http-client) uses for its
`java.net` / `java.io` shims. `libcrypto`/`libssl` are declared `:jolt/native`
and loaded before the namespace; an app that also pulls http-client shares the
one loaded copy (jolt.deps reconciles natives).

## Test

```
joltc -M:test
```
