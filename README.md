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

```clojure
(require 'jolt.crypto)   ;; installs the host-class shims on load
```

The shims register through Jolt's host-shim hooks (`__register-class-ctor!` /
`__register-class-statics!` / `__register-class-methods!`) — the same seam
[jolt-lang/http-client](https://github.com/jolt-lang/http-client) uses for its
`java.net` / `java.io` shims. `libcrypto`/`libssl` are declared `:jolt/native`
and loaded before the namespace; an app that also pulls http-client shares the
one loaded copy (jolt.deps reconciles natives).

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
| `:key-size` | `generate` only: RSA modulus bits, or 256, 384 or 521 to pick the EC curve |

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

## OpenSSL

The library needs OpenSSL 3 at runtime. It is looked for in:

- **macOS:** Homebrew (`/opt/homebrew/opt/openssl@3/lib`, `/usr/local/opt/openssl@3/lib`),
  MacPorts (`/opt/local/lib`), then `libcrypto.3.dylib` / `libssl.3.dylib` on the
  dynamic loader's path. Never `/usr/lib/libcrypto.dylib`: that is Apple's stub,
  and opening it aborts the process.
- **Linux:** `libcrypto.so.3`, `libcrypto.so.1.1`, `libcrypto.so` (and the `libssl` equivalents).
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
