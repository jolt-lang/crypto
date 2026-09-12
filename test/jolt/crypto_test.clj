(ns jolt.crypto-test
  "Drives the shims through the javax.crypto / java.security surface, exactly the
  way ring-core's session-cookie store does."
  (:require [jolt.crypto]
            [clojure.string :as str]))

(import '[javax.crypto Cipher Mac])
(import '[javax.crypto.spec SecretKeySpec IvParameterSpec])
(import '[java.security SecureRandom MessageDigest KeyPairGenerator Signature KeyFactory])
(import '[java.security.spec ECGenParameterSpec X509EncodedKeySpec PKCS8EncodedKeySpec])
(import '[java.security.cert CertificateFactory X509Certificate Certificate CertificateException])

(def ^:private failures (atom 0))
(defn- check [label ok?] (println (if ok? "ok  " "FAIL") label) (when-not ok? (swap! failures inc)))

(defn- ba= [a b] (= (seq a) (seq b)))

(defn- hex [d] (apply str (map #(format "%02x" (bit-and % 0xff)) (seq d))))

(defn- unhex [s]
  (byte-array (map (fn [[a b]] (unchecked-byte (Integer/parseInt (str a b) 16)))
                   (partition 2 s))))

(def ^:private foo (byte-array (map int "foo")))
(def ^:private k (byte-array (map int "k")))

(defn- encrypt [key data]
  (let [iv (byte-array (repeatedly 16 #(rand-int 256)))
        cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
    (.init cipher Cipher/ENCRYPT_MODE (SecretKeySpec. key "AES") (IvParameterSpec. iv))
    {:iv iv :ct (.doFinal cipher data)}))

(defn- decrypt [key iv ct]
  (let [cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
    (.init cipher Cipher/DECRYPT_MODE (SecretKeySpec. key "AES") (IvParameterSpec. iv))
    (.doFinal cipher ct)))

(defn- test-large-input-digest []
  ;; update() used to box and retain one value per byte, then digest() walked
  ;; them all again. The fixed path is comfortably below this bound; the stock
  ;; implementation takes many times longer for the same 16 MiB input.
  (let [buf (byte-array (* 16 1024 1024))
        start (System/nanoTime)
        md (MessageDigest/getInstance "SHA-256")]
    (.update md buf)
    (.digest md)
    (let [ms (/ (- (System/nanoTime) start) 1000000.0)]
      (check (str "a 16 MiB digest completes within 5 seconds (" ms " ms)")
             (< ms 5000.0)))))

(defn- test-update-snapshots-input []
  (let [original (.getBytes "hello world")
        expected (.digest (MessageDigest/getInstance "SHA-256") original)
        input (.getBytes "hello world")
        md (MessageDigest/getInstance "SHA-256")]
    (.update md input)
    (aset input 0 (byte (int \H)))
    (check "MessageDigest.update snapshots caller bytes"
           (ba= expected (.digest md)))))

;; A self-signed EC certificate: CN=jolt.test, O=Jolt, C=US, serial 0x12345678,
;; valid 2026-01-01 to 2036-01-01, ecdsa-with-SHA256. Every expected value
;; below is what OpenJDK 21's X509CertImpl answers for this same PEM.
(def ^:private test-cert-pem
  "-----BEGIN CERTIFICATE-----\nMIIBpTCCAUugAwIBAgIEEjRWeDAKBggqhkjOPQQDAjAwMRIwEAYDVQQDDAlqb2x0\nLnRlc3QxDTALBgNVBAoMBEpvbHQxCzAJBgNVBAYTAlVTMB4XDTI2MDEwMTAwMDAw\nMFoXDTM2MDEwMTAwMDAwMFowMDESMBAGA1UEAwwJam9sdC50ZXN0MQ0wCwYDVQQK\nDARKb2x0MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA2S\nRF8eJAyz8DfbzvJBorsdNCFbnP0TdB1eHXqFEWjZRY/Xc6vYdCx2CD6VDwMcCzk/\n5L8Gbiu48yMAv5IYu8WjUzBRMB0GA1UdDgQWBBQixWjb0UMb3v62Oyjvj/dJaC0s\nPzAfBgNVHSMEGDAWgBQixWjb0UMb3v62Oyjvj/dJaC0sPzAPBgNVHRMBAf8EBTAD\nAQH/MAoGCCqGSM49BAMCA0gAMEUCIEp4nblFz7LDjX+XqrPfhmygZW4dj9GPFaG8\nM5m01PH7AiEA/eiV4/JxqoCXlAbCvCqmBT2LiJBp9RJXOFeVu32HpkE=\n-----END CERTIFICATE-----\n")

(defn- test-x509-certificates []
  (let [cf (CertificateFactory/getInstance "X.509")
        cert (.generateCertificate cf (java.io.ByteArrayInputStream. (.getBytes test-cert-pem)))]
    (check "CertificateFactory type" (= "X.509" (.getType cf)))
    (check "X509 is recognised" (= "X509" (.getType (CertificateFactory/getInstance "X509"))))
    (check "an unknown type is a CertificateException"
           (= ["java.security.cert.CertificateException" "Bogus not found"]
              (try (CertificateFactory/getInstance "Bogus") :no-throw
                   (catch CertificateException e [(.getName (class e)) (.getMessage e)]))))
    (check "certificate type" (= "X.509" (.getType cert)))
    (check "class" (= "java.security.cert.X509Certificate" (.getName (class cert))))
    (check "instance? X509Certificate" (instance? X509Certificate cert))
    (check "instance? Certificate" (instance? Certificate cert))
    (check "subject (RFC 2253)" (= "C=US,O=Jolt,CN=jolt.test" (.getName (.getSubjectX500Principal cert))))
    (check "issuer (RFC 2253)" (= "C=US,O=Jolt,CN=jolt.test" (.getName (.getIssuerX500Principal cert))))
    (check "subject DN (RFC 1779)" (= "C=US, O=Jolt, CN=jolt.test" (.getName (.getSubjectDN cert))))
    (check "subject DN toString" (= "C=US, O=Jolt, CN=jolt.test" (str (.getSubjectDN cert))))
    (check "X500Principal getName RFC1779" (= "C=US, O=Jolt, CN=jolt.test" (.getName (.getSubjectX500Principal cert) "RFC1779")))
    (check "X500Principal equality" (= (.getSubjectX500Principal cert) (.getIssuerX500Principal cert)))
    (check "X500Principal from a string" (= (javax.security.auth.x500.X500Principal. "C=US,O=Jolt,CN=jolt.test") (.getSubjectX500Principal cert)))
    (check "serial number" (= 305419896 (.getSerialNumber cert)))
    (check "notBefore" (= 1767225600000 (.getTime (.getNotBefore cert))))
    (check "notAfter" (= 2082758400000 (.getTime (.getNotAfter cert))))
    (check "version" (= 3 (.getVersion cert)))
    (check "signature algorithm name" (= "SHA256withECDSA" (.getSigAlgName cert)))
    (check "signature algorithm OID" (= "1.2.840.10045.4.3.2" (.getSigAlgOID cert)))
    (check "public key algorithm" (= "EC" (.getAlgorithm (.getPublicKey cert))))
    (check "public key format" (= "X.509" (.getFormat (.getPublicKey cert))))
    (check "public key DER length" (= 91 (alength (.getEncoded (.getPublicKey cert)))))
    (check "encoded DER length" (= 425 (alength (.getEncoded cert))))
    (check "DER round-trips through the factory"
           (ba= (.getEncoded cert)
                (.getEncoded (.generateCertificate cf (java.io.ByteArrayInputStream. (.getEncoded cert))))))
    (check "the public key verifies the certificate's own signature (self-signed)"
           (let [kf (KeyFactory/getInstance "EC")
                 pub (.generatePublic kf (X509EncodedKeySpec. (.getEncoded (.getPublicKey cert))))]
             (some? pub)))
    (check "checkValidity now" (nil? (.checkValidity cert)))
    (check "checkValidity before notBefore"
           (= "java.security.cert.CertificateNotYetValidException"
              (try (.checkValidity cert (java.util.Date. 0)) :no-throw
                   (catch CertificateException e (.getName (class e))))))
    (check "checkValidity after notAfter"
           (= "java.security.cert.CertificateExpiredException"
              (try (.checkValidity cert (java.util.Date. 4102444800000)) :no-throw
                   (catch Exception e (.getName (class e))))))
    (check "a PEM bundle yields every certificate"
           (= 2 (count (.generateCertificates cf (java.io.ByteArrayInputStream. (.getBytes (str test-cert-pem test-cert-pem)))))))
    (check "equal by encoding" (= cert (.generateCertificate cf (java.io.ByteArrayInputStream. (.getBytes test-cert-pem)))))
    (check "hash by encoding" (= (hash cert) (hash (.generateCertificate cf (java.io.ByteArrayInputStream. (.getBytes test-cert-pem))))))
    (check "unparseable input is a CertificateException"
           (= ["java.security.cert.CertificateException" "Could not parse certificate: java.io.IOException: Empty input"]
              (try (.generateCertificate cf (java.io.ByteArrayInputStream. (.getBytes "not a cert"))) :no-throw
                   (catch Exception e [(.getName (class e)) (.getMessage e)]))))
    (check "toString names the subject" (str/includes? (str cert) "Subject: C=US, O=Jolt, CN=jolt.test"))))

(defn -main [& _]
  (test-large-input-digest)
  (test-update-snapshots-input)
  (test-x509-certificates)

  ;; SecureRandom fills a buffer with (probably) non-zero, varying bytes.
  (let [sr (SecureRandom.) a (byte-array 16) b (byte-array 16)]
    (.nextBytes sr a) (.nextBytes sr b)
    (check "SecureRandom fills" (= 16 (alength a)))
    (check "SecureRandom varies" (not (ba= a b))))

  ;; AES-128 round-trip
  (let [key (byte-array (range 16))
        msg (byte-array (map int "the quick brown fox jumps over the lazy dog"))
        {:keys [iv ct]} (encrypt key msg)]
    (check "AES-128 round-trips" (ba= msg (decrypt key iv ct)))
    (check "AES ciphertext differs from plaintext" (not (ba= msg ct))))

  ;; AES-256 round-trip (32-byte key picks the 256 variant)
  (let [key (byte-array (range 32))
        msg (byte-array (map int "secret"))
        {:keys [iv ct]} (encrypt key msg)]
    (check "AES-256 round-trips" (ba= msg (decrypt key iv ct))))

  ;; HMAC-SHA256: deterministic, 32 bytes, key-sensitive
  (let [data (byte-array (map int "message"))
        mac1 (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 16)) "HmacSHA256")) (.doFinal m data))
        mac1' (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 16)) "HmacSHA256")) (.doFinal m data))
        mac2 (let [m (Mac/getInstance "HmacSHA256")] (.init m (SecretKeySpec. (byte-array (range 1 17)) "HmacSHA256")) (.doFinal m data))]
    (check "HMAC is 32 bytes" (= 32 (alength mac1)))
    (check "HMAC is deterministic" (ba= mac1 mac1'))
    (check "HMAC is key-sensitive" (not (ba= mac1 mac2))))

  ;; SHA-256 of "abc" — known vector ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  (let [md (MessageDigest/getInstance "SHA-256")
        d  (.digest md (byte-array (map int "abc")))
        hex (apply str (map #(format "%02x" (bit-and % 0xff)) (seq d)))]
    (check "SHA-256(abc) matches NIST vector"
           (= hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")))

  ;; update-then-digest accumulates: digest(bytes) appends to the updated
  ;; state (the JVM contract clj-uuid's digest-bytes relies on), so the split
  ;; feed equals the one-shot digest of the concatenation.
  (let [one (.digest (MessageDigest/getInstance "SHA-256") (byte-array (map int "abc")))
        two (let [md (MessageDigest/getInstance "SHA-256")]
              (.update md (byte-array (map int "ab")))
              (.digest md (byte-array (map int "c"))))
        three (let [md (MessageDigest/getInstance "SHA-256")]
                (.update md (byte-array (map int "a")))
                (.update md (byte-array (map int "b")))
                (.digest md (byte-array (map int "c"))))]
    (check "update then digest equals one-shot" (ba= one two))
    (check "updates accumulate across calls" (ba= one three)))

  ;; MD5 of "abc" — known vector 900150983cd24fb0d6963f7d28e17f72
  (let [md (MessageDigest/getInstance "MD5")
        d  (.digest md (byte-array (map int "abc")))
        hex (apply str (map #(format "%02x" (bit-and % 0xff)) (seq d)))]
    (check "MD5(abc) matches known vector"
           (= hex "900150983cd24fb0d6963f7d28e17f72")))

  ;; SHA-2 family over "foo" — hex vectors measured on the reference JVM
  (doseq [[algo len expected]
          [["MD5"     16 "acbd18db4cc2f85cedef654fccc4a4d8"]
           ["SHA-1"   20 "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"]
           ["SHA-224" 28 "0808f64e60d58979fcb676c96ec938270dea42445aeefcd3a4e6f8db"]
           ["SHA-256" 32 "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"]
           ["SHA-384" 48 "98c11ffdfdd540676b1a137cb1a22b2a70350c9a44171d6b1180c6be5cbb2ee3f79d532c8a1dd9ef2e8e08e752a3babb"]
           ["SHA-512" 64 "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"]]]
    (let [d (.digest (MessageDigest/getInstance algo) foo)]
      (check (str algo "(foo) is " len " bytes") (= len (alength d)))
      (check (str algo "(foo) matches JVM vector") (= expected (hex d)))))

  ;; the dashless spelling resolves to the same digest
  (check "SHA512 alias matches SHA-512"
         (= (hex (.digest (MessageDigest/getInstance "SHA-512") foo))
            (hex (.digest (MessageDigest/getInstance "SHA512") foo))))

  ;; HMAC over "foo" with key "k" — hex vectors measured on the reference JVM
  ;; (HmacSHA384 measured via OpenSSL; its SHA-256/512 outputs match the JVM
  ;; vectors byte-for-byte, so the measurement is authoritative)
  (doseq [[algo len expected]
          [["HmacSHA1"   20 "7a19f035e2380ef9611f621a635ee1062418880a"]
           ["HmacSHA256" 32 "dc9652dbf73f8c8e4f8d522960bd624b011981816111ce435979a911e929aba5"]
           ["HmacSHA384" 48 "fbd8da1a4a002a279c5bfe96950f7c4b893467b63accb010bde2ec380169101a81f541e968e8ac71391fd4d2740e45c4"]
           ["HmacSHA512" 64 "5df9826d89479edcc2aa25c2336798fca37f760ddc249adc96843692bea2c71610d4e14ba2580181bd86ac6f0f71bf4b1e2bc1c15fe28a1c97a5bebd0b355166"]]]
    (let [m (Mac/getInstance algo)]
      (.init m (SecretKeySpec. k algo))
      (let [d (.doFinal m foo)]
        (check (str algo "(k, foo) is " len " bytes") (= len (alength d)))
        (check (str algo "(k, foo) matches JVM vector") (= expected (hex d)))
        (check (str algo " getMacLength") (= len (.getMacLength m))))))

  ;; unknown algorithms throw, naming the algorithm
  (let [msg (try (MessageDigest/getInstance "WHIRLPOOL") nil
                 (catch Exception e (.getMessage e)))]
    (check "unknown MessageDigest algorithm throws naming it"
           (= msg "unsupported MessageDigest algorithm: WHIRLPOOL")))
  (let [msg (try (Mac/getInstance "HmacWHIRLPOOL") nil
                 (catch Exception e (.getMessage e)))]
    (check "unknown Mac algorithm throws naming it"
           (= msg "unsupported Mac algorithm: HmacWHIRLPOOL")))

  ;; --- EC keys and ECDSA ----------------------------------------------------
  ;; A P-256 keypair encodes to the same lengths the JVM produces: 91 bytes of
  ;; X.509 SubjectPublicKeyInfo, and a PKCS#8 PrivateKeyInfo. OpenSSL's PKCS#8
  ;; carries the optional public key where the JDK's does not, so the private
  ;; length legitimately differs from the JDK's 67; both parse on either side.
  (let [kpg (doto (KeyPairGenerator/getInstance "EC") (.initialize (ECGenParameterSpec. "secp256r1")))
        kp  (.genKeyPair kpg)
        pub (.getEncoded (.getPublic kp))
        priv (.getEncoded (.getPrivate kp))
        data (byte-array (map int "sign me"))]
    (check "P-256 public key is a 91-byte X.509 SPKI" (= 91 (alength pub)))
    (check "P-256 public key DER starts with SEQUENCE" (= 0x30 (bit-and (aget pub 0) 0xff)))
    (check "public key reports EC / X.509" (and (= "EC" (.getAlgorithm (.getPublic kp)))
                                                (= "X.509" (.getFormat (.getPublic kp)))))
    (check "private key reports EC / PKCS#8" (and (= "EC" (.getAlgorithm (.getPrivate kp)))
                                                  (= "PKCS#8" (.getFormat (.getPrivate kp)))))
    (check "two keypairs differ" (not (ba= pub (.getEncoded (.getPublic (.genKeyPair kpg))))))

    ;; sign / verify round-trip through KeyFactory, the way a caller who has
    ;; only the encoded bytes has to do it
    (let [kf (KeyFactory/getInstance "EC")
          sk (.generatePrivate kf (PKCS8EncodedKeySpec. priv))
          pk (.generatePublic kf (X509EncodedKeySpec. pub))
          sig (doto (Signature/getInstance "SHA256withECDSA") (.initSign sk) (.update data))
          s (.sign sig)]
      (check "ECDSA signature is a DER SEQUENCE" (= 0x30 (bit-and (aget s 0) 0xff)))
      (check "signature verifies"
             (-> (doto (Signature/getInstance "SHA256withECDSA") (.initVerify pk) (.update data))
                 (.verify s)))
      (check "Signature.update snapshots caller bytes"
             (let [input (byte-array (map int "sign me"))
                   signer (doto (Signature/getInstance "SHA256withECDSA")
                            (.initSign sk)
                            (.update input))]
               (aset input 0 (byte (int \S)))
               (-> (doto (Signature/getInstance "SHA256withECDSA")
                     (.initVerify pk)
                     (.update data))
                   (.verify (.sign signer)))))
      (check "tampered data fails"
             (not (-> (doto (Signature/getInstance "SHA256withECDSA") (.initVerify pk)
                        (.update (byte-array (map int "sign ME"))))
                      (.verify s))))
      (check "a malformed signature is false, not a throw"
             (false? (-> (doto (Signature/getInstance "SHA256withECDSA") (.initVerify pk) (.update data))
                         (.verify (byte-array 8)))))
      (check "another key's signature fails"
             (let [other (.getPublic (.genKeyPair kpg))]
               (not (-> (doto (Signature/getInstance "SHA256withECDSA") (.initVerify other) (.update data))
                        (.verify s)))))
      ;; update accumulates, so a split feed signs the same bytes as one call
      (check "split update matches a single update"
             (-> (doto (Signature/getInstance "SHA256withECDSA") (.initVerify pk)
                   (.update (byte-array (map int "sign")))
                   (.update (byte-array (map int " me"))))
                 (.verify s)))))

  ;; Known-answer vector: key and signature generated on the reference JVM
  ;; (Clojure 1.12.3 / SHA256withECDSA). Verifying it here proves the shims
  ;; interoperate with real JVM output rather than only with themselves.
  (let [pub  (unhex "3059301306072a8648ce3d020106082a8648ce3d03010703420004188cdf274dba76ea09c9bcf7c4f8bb4dc821a3cb3ec469db466feebc99b4a720f6fb0950fc87b12ed9f1954a28a4af697f4233a053f8567a6ae889875c286e0f")
        priv (unhex "3041020100301306072a8648ce3d020106082a8648ce3d0301070427302502010104208ba51c78232e7814c60584a588cd117946b2bb6ae0cb375b5e9b78eec6f6ff0f")
        sig  (unhex "304402202938601226d18b8468496a204ee30cfa17a53b96fc0dd6db73612f6cf328c8770220703004f1f2be8836a7c208d8195158eca27d1334a42750d7fe47d798251147b0")
        data (byte-array (map int "jolt-crypto ECDSA known-answer vector"))
        kf   (KeyFactory/getInstance "EC")
        pk   (.generatePublic kf (X509EncodedKeySpec. pub))]
    (check "verifies a signature produced by the JVM"
           (-> (doto (Signature/getInstance "SHA256withECDSA") (.initVerify pk) (.update data))
               (.verify sig)))
    ;; the JDK's shorter PKCS#8 (no embedded public key) parses too, and a
    ;; signature made from it verifies against the JVM-generated public key
    (check "signs with the JDK's 67-byte PKCS#8"
           (let [sk (.generatePrivate kf (PKCS8EncodedKeySpec. priv))
                 s  (-> (doto (Signature/getInstance "SHA256withECDSA") (.initSign sk) (.update data))
                        .sign)]
             (-> (doto (Signature/getInstance "SHA256withECDSA") (.initVerify pk) (.update data))
                 (.verify s)))))

  ;; the other digests and curves resolve, and .initialize takes a key size
  (doseq [algo ["SHA1withECDSA" "SHA384withECDSA" "SHA512withECDSA"]]
    (let [kp (.genKeyPair (KeyPairGenerator/getInstance "EC"))
          data (byte-array (map int "multi-digest"))
          s (-> (doto (Signature/getInstance algo) (.initSign (.getPrivate kp)) (.update data)) .sign)]
      (check (str algo " round-trips")
             (-> (doto (Signature/getInstance algo) (.initVerify (.getPublic kp)) (.update data))
                 (.verify s)))))
  ;; Lengths measured on the reference JVM. prime256v1 and P-256 are aliases the
  ;; JDK's provider does not take; accepting them is a superset, not a divergence.
  (doseq [[curve len] [["secp256r1" 91] ["NIST P-256" 91] ["prime256v1" 91] ["P-256" 91]
                       ["secp384r1" 120] ["secp521r1" 158]]]
    (let [kpg (doto (KeyPairGenerator/getInstance "EC") (.initialize (ECGenParameterSpec. curve)))]
      (check (str curve " public key is " len " bytes")
             (= len (alength (.getEncoded (.getPublic (.genKeyPair kpg))))))))
  (let [kpg (doto (KeyPairGenerator/getInstance "EC") (.initialize 384))]
    (check "initialize(int) selects the P-curve of that size"
           (= 120 (alength (.getEncoded (.getPublic (.genKeyPair kpg)))))))

  ;; unknown algorithms and curves throw, naming what was asked for
  (check "unknown Signature algorithm throws naming it"
         (= "unsupported Signature algorithm: SHA256withRSA"
            (try (Signature/getInstance "SHA256withRSA") nil (catch Exception e (.getMessage e)))))
  (check "unknown curve throws naming it"
         (= "unsupported EC curve: brainpoolP256r1"
            (try (.initialize (KeyPairGenerator/getInstance "EC") (ECGenParameterSpec. "brainpoolP256r1"))
                 nil (catch Exception e (.getMessage e)))))
  (check "a non-EC KeyPairGenerator throws naming it"
         (= "unsupported KeyPairGenerator algorithm: RSA"
            (try (KeyPairGenerator/getInstance "RSA") nil (catch Exception e (.getMessage e)))))
  (check "garbage key bytes are rejected at generatePublic"
         (= "not a valid DER-encoded EC key"
            (try (.generatePublic (KeyFactory/getInstance "EC") (X509EncodedKeySpec. (byte-array 10)))
                 nil (catch Exception e (.getMessage e)))))

  ;; java.security.SecureRandom — the whole surface, because this registration
  ;; overrides jolt's native class whenever this namespace loads. A narrower shim
  ;; here silently removed nextInt/nextLong from any program that required
  ;; jolt.crypto for something unrelated.
  (let [r (java.security.SecureRandom.)]
    (check "nextBytes fills the buffer"
           (let [b (byte-array 32)] (.nextBytes r b) (> (count (distinct (seq b))) 8)))
    (check "generateSeed returns the requested length" (= 32 (alength (.generateSeed r 32))))
    (check "nextInt bound stays in range"
           (every? #(and (>= % 0) (< % 10)) (repeatedly 500 #(.nextInt r 10))))
    (check "nextInt bound covers the range" (= 10 (count (distinct (repeatedly 500 #(.nextInt r 10))))))
    (check "nextInt is not a constant" (> (count (distinct (repeatedly 200 #(.nextInt r)))) 190))
    (check "nextLong is not a constant" (> (count (distinct (repeatedly 200 #(.nextLong r)))) 190))
    (check "nextDouble is in [0,1)" (every? #(and (>= % 0.0) (< % 1.0)) (repeatedly 200 #(.nextDouble r))))
    (check "nextFloat is in [0,1)" (every? #(and (>= % 0.0) (< % 1.0)) (repeatedly 200 #(.nextFloat r))))
    (check "nextBoolean yields both" (= #{true false} (set (repeatedly 200 #(.nextBoolean r)))))
    (check "setSeed does not break the generator" (do (.setSeed r 42) (int? (.nextInt r 100))))
    (check "a non-positive bound throws"
           (= :threw (try (.nextInt r 0) :no-throw (catch Exception e :threw))))
    (check "getInstance returns a working generator"
           (int? (.nextInt (java.security.SecureRandom/getInstance "SHA1PRNG") 100)))
    (check "getInstanceStrong returns a working generator"
           (int? (.nextInt (java.security.SecureRandom/getInstanceStrong) 100))))

  (if (zero? @failures)
    (println "\nALL CRYPTO TESTS PASSED")
    (do (println "\n" @failures "FAILURES") (System/exit 1))))
