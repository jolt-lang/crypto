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
| `java.security.KeyPairGenerator` | EC keygen over P-256 / P-384 / P-521 / secp256k1, and RSA keygen (512–16384 bits, default 2048, exponent 65537) |
| `java.security.Signature` | `SHA1`/`SHA224`/`SHA256`/`SHA384`/`SHA512withECDSA` and `…withRSA` |
| `java.security.KeyFactory` | EC and RSA keys from encoded DER |
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

## OpenSSL

The library needs OpenSSL 3 at runtime. It is looked for in:

- **macOS:** Homebrew (`/opt/homebrew/opt/openssl@3/lib`, `/usr/local/opt/openssl@3/lib`),
  MacPorts (`/opt/local/lib`), then `libcrypto.3.dylib` / `libssl.3.dylib` on the
  dynamic loader's path. Never `/usr/lib/libcrypto.dylib`: that is Apple's stub,
  and opening it aborts the process. Without OpenSSL installed the program fails
  with jolt's "required native library crypto not found" instead.
- **Linux:** `libcrypto.so.3`, `libcrypto.so.1.1`, `libcrypto.so` (and the `libssl` equivalents).
- **Windows:** `libcrypto-3-x64.dll` and the other names OpenSSL's builds ship, beside
  the executable or on `PATH`.

To link OpenSSL into a `jolt build` binary instead, add the static archives
in your app's `deps.edn`. The library already declares what `libcrypto.a`
itself links against (`:link-libs`: `ws2_32 gdi32 crypt32` on Windows,
`dl pthread` on Linux), which jolt 0.8.16 and later add to the link:

```clojure
:jolt/native [{:name "crypto" :static {:archive "/mingw64/lib/libcrypto.a"}}
              {:name "ssl"    :static {:archive "/mingw64/lib/libssl.a"}}]
```

## Test

```
jolt -M:test
```
