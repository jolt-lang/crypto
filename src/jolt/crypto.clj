(ns jolt.crypto
  "Symmetric crypto for Jolt, bound to the system OpenSSL (libcrypto) through
  jolt.ffi, and exposed as the small slice of the `javax.crypto` / `java.security`
  surface that real Clojure libraries touch:

    Cipher        AES/CBC/PKCS5Padding (128/192/256, key length picks the variant)
    Mac           HmacSHA512 / HmacSHA384 / HmacSHA256 / HmacSHA1
    MessageDigest SHA-512 / SHA-384 / SHA-256 / SHA-224 / SHA-1 / MD5
    SecureRandom  RAND_bytes
    SecretKeySpec / IvParameterSpec   key + IV holders
    KeyPairGenerator   EC over the NIST P-curves, RSA and Ed25519
    Signature      ECDSA, RSA PKCS#1 v1.5/PSS, Ed25519 and Ed448
    KeyFactory   EC/RSA/DSA/Ed25519/Ed448, with X509EncodedKeySpec /
                  PKCS8EncodedKeySpec / ECGenParameterSpec and PEM decoding
    CertificateFactory   X.509 certificates from PEM or DER, as X509Certificate
                  values (subject/issuer X500Principal, validity, serial,
                  signature algorithm, public key, getEncoded)

  This is enough for ring-core's encrypted session-cookie store and the CSRF
  token machinery, so ring-defaults loads and runs. Shim objects are host
  tagged-tables (jolt.host/tagged-table) whose fields are read/written with
  ref-get / ref-put!; everything registers through Jolt's host-shim hooks
  (__register-class-ctor! / __register-class-statics! / __register-class-methods!),
  the same seam jolt-lang/http-client uses for its java.net / java.io shims.

  libcrypto/libssl are declared in deps.edn :jolt/native and loaded before this
  namespace; an app that also pulls http-client shares the one loaded copy."
  (:require [jolt.ffi :as ffi]
            [jolt.crypto.internal.libcrypto :as lc]
            [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.internal.pkcs8 :as pkcs8]
            [jolt.crypto.internal.support :refer [->ba as-ba ba-window concat-bas
                                                  consume-update-args der-out
                                                  pkey-type ptr-size table? tget
                                                  tput! tt with-mem-bio with-ptrs]]
            [jolt.crypto.internal.x509 :as x509]
            [clojure.string :as str]))


(defn- evp-cipher-for [keylen]
  (case keylen 16 (lc/c-aes128) 24 (lc/c-aes192) 32 (lc/c-aes256)
    (throw (ex-info (str "AES key must be 16/24/32 bytes, got " keylen) {:keylen keylen}))))

;; --- AES-CBC (PKCS5/PKCS7 padding is EVP's CBC default) ---------------------
(defn aes-cbc [encrypt? key iv data]
  (let [key (as-ba key) iv (as-ba iv) data (as-ba data)
        ctx (lc/c-ctx-new) ciph (evp-cipher-for (alength key)) inlen (alength data)]
    (with-ptrs [key iv data]
      (fn [keyp ivp inp]
        (let [outp (ffi/alloc (+ inlen 32)) outlp (ffi/alloc 4)
              [init upd fin] (if encrypt? [lc/c-enc-init lc/c-enc-upd lc/c-enc-fin]
                                          [lc/c-dec-init lc/c-dec-upd lc/c-dec-fin])]
          (try
            (when (not= 1 (init ctx ciph ffi/null keyp ivp)) (throw (ex-info "cipher init failed" {})))
            (when (not= 1 (upd ctx outp outlp inp inlen)) (throw (ex-info "cipher update failed" {})))
            (let [n1 (ffi/read outlp :int)]
              (when (not= 1 (fin ctx (+ outp n1) outlp))
                (throw (ex-info (if encrypt? "cipher final failed" "bad padding / wrong key") {})))
              (ffi/read-array outp (+ n1 (ffi/read outlp :int))))
            (finally (lc/c-ctx-free ctx) (ffi/free outp) (ffi/free outlp))))))))

;; --- HMAC -------------------------------------------------------------------
(defn hmac [md-fn outlen key data]
  (let [key (as-ba key) data (as-ba data) kl (alength key) dl (alength data)]
    (with-ptrs [key data]
      (fn [kp dp]
        (let [mdp (ffi/alloc 64)]
          (try (lc/c-hmac (md-fn) kp kl dp dl mdp ffi/null) (ffi/read-array mdp outlen)
               (finally (ffi/free mdp))))))))

;; --- digest -----------------------------------------------------------------
(defn digest [md-fn outlen data]
  (let [data (as-ba data) dl (alength data)]
    (with-ptrs [data]
      (fn [dp]
        (let [mdp (ffi/alloc 64) lenp (ffi/alloc 4)]
          (try (when (not= 1 (lc/c-digest dp dl mdp lenp (md-fn) ffi/null))
                 (throw (ex-info "digest failed" {})))
               (ffi/read-array mdp outlen)
               (finally (ffi/free mdp) (ffi/free lenp))))))))

(defn random-bytes [n]
  (let [p (ffi/alloc (max 1 n))]
    (try (when (not= 1 (lc/c-rand p n)) (throw (ex-info "RAND_bytes failed" {})))
         (ffi/read-array p n)
         (finally (ffi/free p)))))

;; --- EC keys ----------------------------------------------------------------
;; Curve NIDs from OpenSSL's obj_mac.h. The JDK's EC provider names these
;; "secp256r1" and "NIST P-256"; prime256v1 (the ANSI X9.62 spelling) and the
;; bare P-256 are accepted here too, so this is a superset of the JDK's set
;; rather than a divergence. secp256k1 is likewise more than the default JDK
;; provider offers.
(def ^:private curve-nids
  {"secp256r1" 415 "prime256v1" 415 "P-256" 415 "NIST P-256" 415
   "secp384r1" 715 "P-384" 715 "NIST P-384" 715
   "secp521r1" 716 "P-521" 716 "NIST P-521" 716
   "secp256k1" 714})

(defn- curve-nid [curve]
  (or (curve-nids (str curve))
      (throw (ex-info (str "unsupported EC curve: " curve) {:curve curve}))))

(defn- with-der-key
  "Decode DER key bytes with a d2i_* parser, run (f pkey), free the key. d2i
  advances the pointer it is handed, hence the separate holder cell."
  [d2i-fn der f]
  (let [der (as-ba der) n (alength der)
        buf (ffi/alloc (max 1 n)) holder (ffi/alloc ptr-size)]
    (try
      (ffi/write-array buf der)
      (ffi/write holder :pointer buf 0)
      (let [pkey (d2i-fn ffi/null holder n)]
        (when (ffi/null? pkey) (throw (ex-info "not a valid DER-encoded key" {})))
        (try (f pkey) (finally (lc/c-pkey-free pkey))))
      (finally (ffi/free buf) (ffi/free holder)))))

(defn- pkey-algo
  "The JDK algorithm name for a parsed OpenSSL key."
  [pkey]
  (case (pkey-type pkey)
    "Ed25519" "EdDSA"
    "Ed448" "EdDSA"
    "X25519" "XDH"
    (pkey-type pkey)))

(defn- check-key-algo
  "Refuse a key that is not the algorithm the caller asked for, as the JDK does
  rather than quietly signing with whatever the key happens to be. Only a
  positive disagreement is an error: either side being unknown lets it pass."
  [want got]
  (when (and want got (not= want got))
    (throw (ex-info (str "key algorithm mismatch: expected " want ", got " got)
                    {:expected want :actual got})))
  got)

(defn- check-key-type [factory key]
  (let [expected (tget factory :key-type)
        actual (tget key :key-type)]
    (when (and expected (not= expected actual))
      (throw (ex-info (str "key type mismatch: expected " expected ", got " actual)
                      {:expected expected :actual actual}))))
  key)

(defn key-type
  "The concrete OpenSSL key type, such as RSA, DSA, EC, Ed25519, or Ed448."
  [key]
  (when (table? key)
    (or (tget key :key-type) (tget key :algo))))

(defn- decoded-key [tag der pkey]
  (doto (tt tag)
    (tput! :bytes der)
    (tput! :algo (pkey-algo pkey))
    (tput! :key-type (pkey-type pkey))))

(defn decode-public-key
  "Decode an X.509 SubjectPublicKeyInfo DER value into a tagged PublicKey."
  [der]
  (let [der (as-ba der)]
    (with-der-key lc/c-d2i-pubkey der #(decoded-key :jolt.crypto/public-key der %))))

(defn decode-private-key
  "Decode a PKCS#8 PrivateKeyInfo DER value into a tagged PrivateKey."
  [der]
  (let [der (as-ba der)]
    (with-der-key lc/c-d2i-privkey der #(decoded-key :jolt.crypto/private-key der %))))

;; Every encrypted key goes through OpenSSL's generic decoder first. Only a
;; pbeWithMD5AndDES-CBC PKCS#8 key, which OpenSSL 3 rejects, falls back to
;; jolt.crypto.internal.pkcs8 (see decode-pem-private-key).
(defn- encrypted-pem? [text]
  (or (str/includes? text "Proc-Type: 4,ENCRYPTED")
      (str/includes? text "-----BEGIN ENCRYPTED PRIVATE KEY-----")))

(defn decode-pem-private-key
  "Decode a traditional or PKCS#8 PEM private key into normalized PKCS#8 DER."
  [bytes passphrase]
  (let [bytes (as-ba bytes)
        text (String. bytes "UTF-8")]
    (when (and (encrypted-pem? text) (nil? passphrase))
      (throw (ex-info "Passphrase is mandatory with encrypted keys." {})))
    (try
      (with-mem-bio bytes
        (fn [bio]
          (let [decode (fn [password]
                         (lc/c-err-clear)
                         (let [pkey (lc/c-pem-read-privkey bio ffi/null ffi/null password)]
                           (when (ffi/null? pkey)
                             (lc/c-err-clear)
                             (throw (ex-info "Could not decode PEM private key" {})))
                           (try
                             (let [p8 (lc/c-pkey->p8 pkey)]
                               (when (ffi/null? p8)
                                 (throw (ex-info "PKCS#8 conversion failed" {})))
                               (try
                                 (decode-private-key (der-out lc/c-i2d-p8 p8))
                                 (finally (lc/c-p8-free p8))))
                             (finally (lc/c-pkey-free pkey)))))]
            (if (nil? passphrase)
              (decode ffi/null)
              (ffi/with-c-string [password passphrase]
                (decode password))))))
      (catch clojure.lang.ExceptionInfo e
        (if (str/includes? text "-----BEGIN ENCRYPTED PRIVATE KEY-----")
          ;; Only legacy pbeWithMD5AndDES keys fall back; any other scheme keeps
          ;; OpenSSL's own failure (a wrong passphrase, say).
          (try
            (decode-private-key (pkcs8/decrypt-md5-des text passphrase))
            (catch clojure.lang.ExceptionInfo fallback
              (throw (if (::pkcs8/not-md5-des (ex-data fallback)) e fallback))))
          (throw e))))))

(defn decode-pem-public-key
  "Decode a PEM SubjectPublicKeyInfo or X.509 certificate public key."
  [bytes]
  (let [bytes (as-ba bytes)
        text (String. bytes "UTF-8")]
    (if (str/includes? text "-----BEGIN CERTIFICATE-----")
      (decode-public-key (:der (:public-key (first (x509/parse-x509 bytes)))))
      (with-mem-bio bytes
        (fn [bio]
          (lc/c-err-clear)
          (let [pkey (lc/c-pem-read-pubkey bio ffi/null ffi/null ffi/null)]
            (when (ffi/null? pkey)
              (lc/c-err-clear)
              (throw (ex-info "Could not decode PEM public key or certificate" {})))
            (try
              (decode-public-key (der-out lc/c-i2d-pubkey pkey))
              (finally (lc/c-pkey-free pkey)))))))))

(defn generate-ec-keypair
  "Generate an EC keypair on `curve`. Returns {:public <X.509 DER> :private <PKCS#8 DER>},
  the same two encodings the JVM's getEncoded hands back."
  [curve]
  (let [eck (lc/c-ec-new-curve (curve-nid curve))]
    (when (ffi/null? eck) (throw (ex-info (str "EC key setup failed for curve " curve) {:curve curve})))
    (try
      (when (not= 1 (lc/c-ec-gen eck)) (throw (ex-info "EC key generation failed" {:curve curve})))
      (let [pkey (lc/c-pkey-new)]
        (try
          (when (not= 1 (lc/c-pkey-set-ec pkey eck)) (throw (ex-info "EC key wrap failed" {})))
          (let [p8 (lc/c-pkey->p8 pkey)]
            (when (ffi/null? p8) (throw (ex-info "PKCS#8 conversion failed" {})))
            (try {:public (der-out lc/c-i2d-pubkey pkey) :private (der-out lc/c-i2d-p8 p8)}
                 (finally (lc/c-p8-free p8))))
          (finally (lc/c-pkey-free pkey))))
      (finally (lc/c-ec-free eck)))))

(defn generate-rsa-keypair
  "Generate an RSA keypair of `bits` with the standard 65537 public exponent.
  Returns {:public <X.509 DER> :private <PKCS#8 DER>}, the same two encodings
  the JVM's getEncoded hands back."
  [bits]
  ;; The JDK's RSA provider accepts 512..16384; OpenSSL shares the lower bound
  ;; but reports a failure only as a 0 return, so reject up front to keep the
  ;; error a value rather than a native failure.
  (when-not (<= 512 bits 16384)
    (throw (ex-info (str "RSA key size must be between 512 and 16384 bits, got " bits)
                    {:bits bits})))
  (let [rsa (lc/c-rsa-new)
        e (lc/c-bn-new)]
    (when (ffi/null? rsa) (throw (ex-info "RSA key setup failed" {})))
    (when (ffi/null? e) (throw (ex-info "BN setup failed" {})))
    (try
      (when (not= 1 (lc/c-bn-set-word e 65537)) (throw (ex-info "BN_set_word failed" {})))
      (when (not= 1 (lc/c-rsa-gen rsa bits e ffi/null))
        (throw (ex-info (str "RSA key generation failed for " bits " bits") {:bits bits})))
      (let [pkey (lc/c-pkey-new)]
        (try
          (when (not= 1 (lc/c-pkey-set-rsa pkey rsa)) (throw (ex-info "RSA key wrap failed" {})))
          (let [p8 (lc/c-pkey->p8 pkey)]
            (when (ffi/null? p8) (throw (ex-info "PKCS#8 conversion failed" {})))
            (try {:public (der-out lc/c-i2d-pubkey pkey) :private (der-out lc/c-i2d-p8 p8)}
                 (finally (lc/c-p8-free p8))))
          (finally (lc/c-pkey-free pkey))))
      (finally (lc/c-bn-free e) (lc/c-rsa-free rsa)))))

(def ^:private nid-ed25519 1087)
(def ^:private nid-ed448 1088)

(def ^:private nid-x25519 1034)

(defn- generate-evp-keypair [nid]
  (let [ctx (lc/c-pkey-ctx-new-id nid ffi/null)]
    (when (ffi/null? ctx) (throw (ex-info "EVP key setup failed" {:nid nid})))
    (try
      (when (not= 1 (lc/c-pkey-keygen-init ctx)) (throw (ex-info "EVP keygen init failed" {:nid nid})))
      (let [holder (ffi/alloc ptr-size)]
        (try
          (ffi/write holder :pointer ffi/null 0)
          (when (not= 1 (lc/c-pkey-keygen ctx holder)) (throw (ex-info "EVP key generation failed" {:nid nid})))
          (let [pkey (ffi/read holder :pointer)]
            (try
              (let [p8 (lc/c-pkey->p8 pkey)]
                (when (ffi/null? p8) (throw (ex-info "PKCS#8 conversion failed" {})))
                (try {:public (der-out lc/c-i2d-pubkey pkey) :private (der-out lc/c-i2d-p8 p8)}
                     (finally (lc/c-p8-free p8))))
              (finally (lc/c-pkey-free pkey))))
          (finally (ffi/free holder))))
      (finally (lc/c-pkey-ctx-free ctx)))))

(defn generate-ed25519-keypair
  "Generate Ed25519 public X.509 and private PKCS#8 DER encodings."
  []
  (generate-evp-keypair nid-ed25519))

;; --- JWK key parameter boundary ---------------------------------------------
;; These functions are public only so the jwk namespaces can share the existing
;; OpenSSL shim. Their values contain bytes, strings, and tagged DER keys only.
(defn- bn-from-unsigned [data]
  (let [data (as-ba data)]
    (with-ptrs [data]
      (fn [ptr]
        (let [bn (lc/c-bn-bin2bn ptr (alength data) ffi/null)]
          (when (ffi/null? bn)
            (throw (ex-info "OpenSSL BIGNUM initialization failed" {})))
          bn)))))

(defn- bn->unsigned [bn]
  (when-not (ffi/null? bn)
    (let [length (quot (+ (lc/c-bn-num-bits bn) 7) 8)
          output (ffi/alloc (max 1 length))]
      (try
        (let [written (lc/c-bn-bn2bin bn output)]
          (when-not (= length written)
            (throw (ex-info "OpenSSL BIGNUM encoding failed"
                            {:expected length :actual written})))
          (ffi/read-array output length))
        (finally (ffi/free output))))))

(defn- rsa-set0! [rsa setter values]
  (let [owned (atom [])]
    (try
      (let [args (mapv (fn [value]
                         (if (nil? value)
                           ffi/null
                           (let [bn (bn-from-unsigned value)]
                             (swap! owned conj bn)
                             bn)))
                       values)]
        (when-not (= 1 (apply setter rsa args))
          (throw (ex-info "OpenSSL RSA parameter initialization failed" {}))))
      (catch Exception e
        (doseq [bn @owned] (lc/c-bn-free bn))
        (lc/c-err-clear)
        (throw e)))))

(defn- check-native-key [check-fn key algorithm]
  (when-not (= 1 (check-fn key))
    (lc/c-err-clear)
    (throw (ex-info (str "Invalid " algorithm " key parameters") {}))))

(defn rsa-public-from-parameters
  "Build a tagged RSA PublicKey from unsigned n and e bytes. JWK-internal."
  [n e]
  (let [rsa (lc/c-rsa-new)]
    (when (ffi/null? rsa)
      (throw (ex-info "OpenSSL RSA allocation failed" {})))
    (try
      (rsa-set0! rsa lc/c-rsa-set0-key [n e nil])
      (let [pkey (lc/c-pkey-new)]
        (when (ffi/null? pkey)
          (throw (ex-info "OpenSSL EVP_PKEY allocation failed" {})))
        (try
          (when-not (= 1 (lc/c-pkey-set-rsa pkey rsa))
            (throw (ex-info "OpenSSL RSA key wrapping failed" {})))
          (decode-public-key (der-out lc/c-i2d-pubkey pkey))
          (finally (lc/c-pkey-free pkey))))
      (finally (lc/c-rsa-free rsa)))))

(defn rsa-private-from-parameters
  "Build a tagged RSA PrivateKey from a complete unsigned parameter map."
  [{:keys [n e d p q dp dq qi]}]
  (let [rsa (lc/c-rsa-new)]
    (when (ffi/null? rsa)
      (throw (ex-info "OpenSSL RSA allocation failed" {})))
    (try
      (rsa-set0! rsa lc/c-rsa-set0-key [n e d])
      (rsa-set0! rsa lc/c-rsa-set0-factors [p q])
      (rsa-set0! rsa lc/c-rsa-set0-crt [dp dq qi])
      (check-native-key lc/c-rsa-check rsa "RSA")
      (let [pkey (lc/c-pkey-new)]
        (when (ffi/null? pkey)
          (throw (ex-info "OpenSSL EVP_PKEY allocation failed" {})))
        (try
          (when-not (= 1 (lc/c-pkey-set-rsa pkey rsa))
            (throw (ex-info "OpenSSL RSA key wrapping failed" {})))
          (let [p8 (lc/c-pkey->p8 pkey)]
            (when (ffi/null? p8)
              (lc/c-err-clear)
              (throw (ex-info "OpenSSL RSA PKCS#8 encoding failed" {})))
            (try
              (decode-private-key (der-out lc/c-i2d-p8 p8))
              (finally (lc/c-p8-free p8))))
          (finally (lc/c-pkey-free pkey))))
      (finally (lc/c-rsa-free rsa)))))

(defn- with-rsa-parameters [key private? f]
  (with-der-key (if private? lc/c-d2i-privkey lc/c-d2i-pubkey) (tget key :bytes)
    (fn [pkey]
      (let [rsa (lc/c-pkey-get-rsa pkey)]
        (when (ffi/null? rsa)
          (lc/c-err-clear)
          (throw (ex-info "Expected an RSA key" {})))
        (try
          (let [holders (ffi/alloc (* 8 ptr-size))]
            (try
              (lc/c-rsa-get0-key rsa holders (+ holders ptr-size) (+ holders (* 2 ptr-size)))
              (lc/c-rsa-get0-factors rsa (+ holders (* 3 ptr-size)) (+ holders (* 4 ptr-size)))
              (lc/c-rsa-get0-crt rsa (+ holders (* 5 ptr-size)) (+ holders (* 6 ptr-size))
                              (+ holders (* 7 ptr-size)))
              (f (bn->unsigned (ffi/read holders :pointer 0))
                 (bn->unsigned (ffi/read holders :pointer ptr-size))
                 (bn->unsigned (ffi/read holders :pointer (* 2 ptr-size)))
                 (bn->unsigned (ffi/read holders :pointer (* 3 ptr-size)))
                 (bn->unsigned (ffi/read holders :pointer (* 4 ptr-size)))
                 (bn->unsigned (ffi/read holders :pointer (* 5 ptr-size)))
                 (bn->unsigned (ffi/read holders :pointer (* 6 ptr-size)))
                 (bn->unsigned (ffi/read holders :pointer (* 7 ptr-size))))
              (finally (ffi/free holders))))
          (finally (lc/c-rsa-free rsa)))))))

(defn rsa-public-parameters
  "Return {:n bytes :e bytes} from a tagged RSA PublicKey. JWK-internal."
  [key]
  (with-rsa-parameters key false
    (fn [n e _ _ _ _ _ _] {:n n :e e})))

(defn rsa-private-parameters
  "Return unsigned RSA key and CRT bytes from a tagged RSA PrivateKey."
  [key]
  (with-rsa-parameters key true
    (fn [n e d p q dp dq qi]
      {:n n :e e :d d :p p :q q :dp dp :dq dq :qi qi})))

(defn- ec-set-public! [eck x y]
  (let [group (lc/c-ec-get0-group eck)
        point (lc/c-ec-point-new group)]
    (when (ffi/null? point)
      (throw (ex-info "OpenSSL EC point allocation failed" {})))
    (let [xbn (atom nil)
          ybn (atom nil)]
      (try
        (reset! xbn (bn-from-unsigned x))
        (reset! ybn (bn-from-unsigned y))
        (when-not (= 1 (lc/c-ec-point-set group point @xbn @ybn ffi/null))
          (lc/c-err-clear)
          (throw (ex-info "OpenSSL EC coordinate initialization failed" {})))
        (when-not (= 1 (lc/c-ec-set-public eck point))
          (lc/c-err-clear)
          (throw (ex-info "OpenSSL EC public key initialization failed" {})))
        (finally
          (lc/c-ec-point-free point)
          (when @xbn (lc/c-bn-free @xbn))
          (when @ybn (lc/c-bn-free @ybn)))))))

(defn- ec-pkey->der [eck private?]
  (let [pkey (lc/c-pkey-new)]
    (when (ffi/null? pkey)
      (throw (ex-info "OpenSSL EVP_PKEY allocation failed" {})))
    (try
      (when-not (= 1 (lc/c-pkey-set-ec pkey eck))
        (throw (ex-info "OpenSSL EC key wrapping failed" {})))
      (if private?
        (let [p8 (lc/c-pkey->p8 pkey)]
          (when (ffi/null? p8)
            (lc/c-err-clear)
            (throw (ex-info "OpenSSL EC PKCS#8 encoding failed" {})))
          (try
            (decode-private-key (der-out lc/c-i2d-p8 p8))
            (finally (lc/c-p8-free p8))))
        (decode-public-key (der-out lc/c-i2d-pubkey pkey)))
      (finally (lc/c-pkey-free pkey)))))

(defn ec-public-from-parameters
  "Build a tagged EC PublicKey from a JWK curve and unsigned x/y bytes."
  [curve x y]
  (let [eck (lc/c-ec-new-curve (curve-nid curve))]
    (when (ffi/null? eck)
      (throw (ex-info (str "Unsupported EC curve: " curve) {:curve curve})))
    (try
      (ec-set-public! eck x y)
      (check-native-key lc/c-ec-check eck "EC")
      (ec-pkey->der eck false)
      (finally (lc/c-ec-free eck)))))

(defn ec-private-from-parameters
  "Build a tagged EC PrivateKey from a JWK curve and unsigned d/x/y bytes."
  [curve d x y]
  (let [eck (lc/c-ec-new-curve (curve-nid curve))]
    (when (ffi/null? eck)
      (throw (ex-info (str "Unsupported EC curve: " curve) {:curve curve})))
    (try
      (ec-set-public! eck x y)
      (let [dbn (bn-from-unsigned d)]
        (try
          (when-not (= 1 (lc/c-ec-set-private eck dbn))
            (lc/c-err-clear)
            (throw (ex-info "OpenSSL EC private key initialization failed" {})))
          (finally (lc/c-bn-free dbn))))
      (check-native-key lc/c-ec-check eck "EC")
      (ec-pkey->der eck true)
      (finally (lc/c-ec-free eck)))))

(def ^:private jwk-curves
  {415 ["P-256" 32] 714 ["secp256k1" 32]
   715 ["P-384" 48] 716 ["P-521" 66]})

(defn- ec-point-fields [eck derive?]
  (let [group (lc/c-ec-get0-group eck)
        nid (lc/c-ec-group-nid group)
        [curve width] (or (get jwk-curves nid)
                          (throw (ex-info "Unsupported EC curve" {:nid nid})))
        existing (lc/c-ec-get0-public eck)
        derive (and (ffi/null? existing) derive?)
        point (if derive (lc/c-ec-point-new group) existing)]
    (when (ffi/null? point)
      (throw (ex-info "EC key has no public point" {})))
    (try
      (when derive
        (when-not (= 1 (lc/c-ec-point-mul group point ffi/null ffi/null
                                       (lc/c-ec-get0-private eck) ffi/null))
          (lc/c-err-clear)
          (throw (ex-info "OpenSSL EC public key derivation failed" {}))))
      (let [expected (inc (* 2 width))
            actual (lc/c-ec-point-octets group point 4 ffi/null 0 ffi/null)]
        (when-not (= expected actual)
          (throw (ex-info "Unexpected EC point width" {:expected expected :actual actual})))
        (let [buffer (ffi/alloc actual)]
          (try
            (when-not (= actual (lc/c-ec-point-octets group point 4 buffer actual ffi/null))
              (throw (ex-info "OpenSSL EC point encoding failed" {})))
            (let [encoded (ffi/read-array buffer actual)]
              {:crv curve
               :x (ba-window encoded 1 width)
               :y (ba-window encoded (inc width) width)})
            (finally (ffi/free buffer)))))
      (finally
        (when derive (lc/c-ec-point-free point))))))

(defn- with-ec-parameters [key private? f]
  (with-der-key (if private? lc/c-d2i-privkey lc/c-d2i-pubkey) (tget key :bytes)
    (fn [pkey]
      (let [eck (lc/c-pkey-get-ec pkey)]
        (when (ffi/null? eck)
          (lc/c-err-clear)
          (throw (ex-info "Expected an EC key" {})))
        (try (f eck) (finally (lc/c-ec-free eck)))))))

(defn ec-public-parameters
  "Return {:crv string :x bytes :y bytes} from a tagged EC PublicKey."
  [key]
  (with-ec-parameters key false #(ec-point-fields % false)))

(defn ec-private-parameters
  "Return curve/public coordinates and unsigned d bytes from an EC PrivateKey."
  [key]
  (with-ec-parameters key true
    (fn [eck]
      (let [private (lc/c-ec-get0-private eck)]
        (when (ffi/null? private)
          (throw (ex-info "EC key has no private scalar" {})))
        (assoc (ec-point-fields eck true)
               :d (bn->unsigned private))))))

(def ^:private ed-curves
  {"Ed25519" [nid-ed25519 32]
   "Ed448" [nid-ed448 57]})

(defn- ed-from-raw [curve raw private?]
  (let [raw (as-ba raw)
        [nid length] (or (get ed-curves curve)
                         (throw (ex-info (str "Unsupported EdDSA curve: " curve)
                                         {:curve curve})))]
    (when-not (= length (alength raw))
      (throw (ex-info (str curve " raw keys must be " length " bytes")
                      {:curve curve :expected length :actual (alength raw)})))
    (with-ptrs [raw]
      (fn [ptr]
        (let [pkey ((if private? lc/c-pkey-new-raw-private lc/c-pkey-new-raw-public)
                    nid ffi/null ptr length)]
          (when (ffi/null? pkey)
            (lc/c-err-clear)
            (throw (ex-info (str "OpenSSL " curve " raw key initialization failed") {})))
          (try
            (if private?
              (let [p8 (lc/c-pkey->p8 pkey)]
                (when (ffi/null? p8)
                  (throw (ex-info (str curve " PKCS#8 encoding failed") {})))
                (try
                  (decode-private-key (der-out lc/c-i2d-p8 p8))
                  (finally (lc/c-p8-free p8))))
              (decode-public-key (der-out lc/c-i2d-pubkey pkey)))
            (finally (lc/c-pkey-free pkey))))))))

(defn ed-private-from-raw
  "Build a tagged Ed25519/Ed448 PrivateKey from its raw private bytes."
  [curve raw]
  (ed-from-raw curve raw true))

(defn ed-public-from-raw
  "Build a tagged Ed25519/Ed448 PublicKey from its raw public bytes."
  [curve raw]
  (ed-from-raw curve raw false))

(defn- ed-raw-from-key [key private? raw-kind]
  (with-der-key (if private? lc/c-d2i-privkey lc/c-d2i-pubkey) (tget key :bytes)
    (fn [pkey]
      (let [length-holder (ffi/alloc 8)]
        (try
          (let [getter (if (= :private raw-kind) lc/c-pkey-get-raw-private lc/c-pkey-get-raw-public)]
            (when-not (= 1 (getter pkey ffi/null length-holder))
              (lc/c-err-clear)
              (throw (ex-info "OpenSSL raw EdDSA key sizing failed" {})))
            (let [length (ffi/read length-holder :size_t)
                  buffer (ffi/alloc length)]
              (try
                (when-not (= 1 (getter pkey buffer length-holder))
                  (lc/c-err-clear)
                  (throw (ex-info "OpenSSL raw EdDSA key extraction failed" {})))
                (ffi/read-array buffer (ffi/read length-holder :size_t))
                (finally (ffi/free buffer)))))
          (finally (ffi/free length-holder)))))))

(defn ed-private-bytes
  "Extract raw private bytes from a tagged EdDSA PrivateKey. JWK-internal."
  [key]
  (ed-raw-from-key key true :private))

(defn ed-public-bytes
  "Extract raw public bytes from a tagged EdDSA PublicKey. JWK-internal."
  [key]
  (ed-raw-from-key key false :public))

(defn ed-derived-public-bytes
  "Derive raw public bytes from a tagged EdDSA PrivateKey. JWK-internal."
  [key]
  (ed-raw-from-key key true :public))

(defn- generate-keypair-for
  "Draw a keypair from a KeyPairGenerator shim's state: {:public :private
  :algo}, ready for the keypair shim."
  [self]
  (let [{:keys [public private]} (case (tget self :algo)
                                   "RSA" (generate-rsa-keypair (tget self :bits))
                                   "EdDSA" (generate-ed25519-keypair)
                                   "XDH" (generate-evp-keypair nid-x25519)
                                   (generate-ec-keypair (tget self :curve)))]
    (doto (tt :jolt.crypto/keypair)
      (tput! :public public)
      (tput! :private private)
      (tput! :algo (tget self :algo))
      (tput! :key-type (case (tget self :algo) "EdDSA" "Ed25519" "XDH" "X25519" (tget self :algo))))))

(def ^:private rsa-pkcs1-pss-padding 6)
(def ^:private rsa-pss-saltlen-digest -1)

(defn- configure-pss! [pctx md-fn]
  (when (ffi/null? pctx)
    (throw (ex-info "RSA-PSS context initialization failed" {})))
  (when (not= 1 (lc/c-rsa-padding pctx rsa-pkcs1-pss-padding))
    (throw (ex-info "RSA-PSS padding setup failed" {})))
  (when (not= 1 (lc/c-rsa-mgf1-md pctx (md-fn)))
    (throw (ex-info "RSA-PSS MGF1 setup failed" {})))
  (when (not= 1 (lc/c-rsa-pss-saltlen pctx rsa-pss-saltlen-digest))
    (throw (ex-info "RSA-PSS salt length setup failed" {}))))

(defn- check-signature-options [pkey want-algo options]
  (check-key-algo want-algo (pkey-algo pkey))
  (when-let [want-type (:key-type options)]
    (check-key-algo want-type (pkey-type pkey))))

(defn pkey-sign
  "Sign `data` with a PKCS#8 DER private key. A nil digest selects PureEdDSA's
  one-shot operation for Ed25519 and Ed448. Options may select RSA-PSS (with
  MGF1 and salt length both tied to the message digest) and a concrete EdDSA
  key type. Native contexts are released on every exit path."
  ([md-fn priv-der data] (pkey-sign md-fn priv-der data nil nil))
  ([md-fn priv-der data want-algo] (pkey-sign md-fn priv-der data want-algo nil))
  ([md-fn priv-der data want-algo options]
   (with-der-key lc/c-d2i-privkey priv-der
     (fn [pkey]
       (check-signature-options pkey want-algo options)
       (let [data (as-ba data) dn (alength data) ctx (lc/c-md-ctx-new)]
         (when (ffi/null? ctx)
           (throw (ex-info "signature context allocation failed" {})))
         (try
           (with-ptrs [data]
             (fn [dp]
               (let [lenp (ffi/alloc 8)]
                 (try
                   (let [pctxp (ffi/alloc ptr-size)]
                     (try
                       (ffi/write pctxp :pointer ffi/null 0)
                       (when (not= 1 (lc/c-dgst-sign-init ctx pctxp (if md-fn (md-fn) ffi/null) ffi/null pkey))
                         (throw (ex-info "signature init failed" {})))
                       (when (:pss options)
                         (configure-pss! (ffi/read pctxp :pointer) md-fn))
                       ;; a null signature buffer asks for the maximum size rather than signing
                       (ffi/write lenp :size_t 0 0)
                       (when (not= 1 (lc/c-dgst-sign ctx ffi/null lenp dp dn))
                         (throw (ex-info "signature sizing failed" {})))
                       (let [sigp (ffi/alloc (ffi/read lenp :size_t))]
                         (try
                           (when (not= 1 (lc/c-dgst-sign ctx sigp lenp dp dn))
                             (throw (ex-info "signing failed" {})))
                           (ffi/read-array sigp (ffi/read lenp :size_t))
                           (finally (ffi/free sigp))))
                       (finally
                         ;; DigestSignInit transferred pctx ownership to ctx.
                         (ffi/free pctxp))))
                   (finally (ffi/free lenp))))))
           (finally (lc/c-md-ctx-free ctx))))))))

(defn pkey-verify
  "Verify a signature over `data` against an X.509 DER public key. Ordinary
  invalid signatures return false. Options have the same PSS and concrete-key
  meaning as pkey-sign, and native resources are released on every exit path."
  ([md-fn pub-der data sig] (pkey-verify md-fn pub-der data sig nil nil))
  ([md-fn pub-der data sig want-algo] (pkey-verify md-fn pub-der data sig want-algo nil))
  ([md-fn pub-der data sig want-algo options]
   (with-der-key lc/c-d2i-pubkey pub-der
     (fn [pkey]
       (check-signature-options pkey want-algo options)
       (let [data (as-ba data) sig (as-ba sig) dn (alength data) sn (alength sig)
             ctx (lc/c-md-ctx-new)]
         (when (ffi/null? ctx)
           (throw (ex-info "verification context allocation failed" {})))
         (try
           (with-ptrs [data sig]
             (fn [dp sp]
               (let [pctxp (ffi/alloc ptr-size)]
                 (try
                   (ffi/write pctxp :pointer ffi/null 0)
                   (when (not= 1 (lc/c-dgst-verify-init ctx pctxp (if md-fn (md-fn) ffi/null) ffi/null pkey))
                     (throw (ex-info "verification init failed" {})))
                   (when (:pss options)
                     (configure-pss! (ffi/read pctxp :pointer) md-fn))
                   ;; a bad signature is a false, not a throw
                   (let [result (lc/c-dgst-verify ctx sp sn dp dn)]
                     (when (not= 1 result)
                       (lc/c-err-clear))
                     (= 1 result))
                   (finally
                     ;; DigestVerifyInit transferred pctx ownership to ctx.
                     (ffi/free pctxp))))))
           (finally (lc/c-md-ctx-free ctx))))))))

;; --- algorithm name -> primitive --------------------------------------------
(defn- mac-md [algo]
  (case (str algo) ("HmacSHA512" "HMACSHA512") [lc/c-sha512 64] ("HmacSHA384" "HMACSHA384") [lc/c-sha384 48]
    ("HmacSHA256" "HMACSHA256") [lc/c-sha256 32] ("HmacSHA1" "HMACSHA1") [lc/c-sha1 20]
    (throw (ex-info (str "unsupported Mac algorithm: " algo) {:algo algo}))))
;; SHA256withECDSA, SHA256withRSA and friends -> [digest, key algorithm]. The
;; JVM spells these without separators and case-insensitively in practice, so
;; match on the upcased form. EVP takes the primitive from the key rather than
;; the name, so the second half is what holds a key to the algorithm it names.
(defn- signature-spec [algo]
  (case (str/upper-case (str algo))
    "SHA512WITHECDSA" [lc/c-sha512 "EC"]
    "SHA384WITHECDSA" [lc/c-sha384 "EC"]
    "SHA256WITHECDSA" [lc/c-sha256 "EC"]
    "SHA224WITHECDSA" [lc/c-sha224 "EC"]
    "SHA1WITHECDSA"   [lc/c-sha1   "EC"]
    "SHA512WITHRSA"   [lc/c-sha512 "RSA"]
    "SHA384WITHRSA"   [lc/c-sha384 "RSA"]
    "SHA256WITHRSA"   [lc/c-sha256 "RSA"]
    "SHA224WITHRSA"   [lc/c-sha224 "RSA"]
    "SHA1WITHRSA"     [lc/c-sha1   "RSA"]
    ;; Bouncy Castle's SHA*withRSAandMGF1 uses MGF1 with the same digest and a
    ;; digest-length salt. OpenSSL needs all three PSS controls set explicitly.
    "SHA512WITHRSAANDMGF1" [lc/c-sha512 "RSA" {:pss true}]
    "SHA384WITHRSAANDMGF1" [lc/c-sha384 "RSA" {:pss true}]
    "SHA256WITHRSAANDMGF1" [lc/c-sha256 "RSA" {:pss true}]
    ;; PureEdDSA hashes internally: no digest, one-shot over the whole message.
    ;; Generic EdDSA accepts either curve; concrete names enforce theirs.
    "ED25519"         [nil "EdDSA" {:key-type "Ed25519"}]
    "ED448"           [nil "EdDSA" {:key-type "Ed448"}]
    "EDDSA"           [nil "EdDSA"]
    (throw (ex-info (str "unsupported Signature algorithm: " algo) {:algo algo}))))

(defn- digest-spec [algo]
  (case (str/upper-case (str algo)) ("SHA-512" "SHA512") [lc/c-sha512 64] ("SHA-384" "SHA384") [lc/c-sha384 48]
    ("SHA-256" "SHA256") [lc/c-sha256 32] ("SHA-224" "SHA224") [lc/c-sha224 28] ("SHA-1" "SHA1") [lc/c-sha1 20]
    ("MD5") [lc/c-md5 16]
    (throw (ex-info (str "unsupported MessageDigest algorithm: " algo) {:algo algo}))))

;; --- host-class shims -------------------------------------------------------
(def ENCRYPT-MODE 1)
(def DECRYPT-MODE 2)

(defn- sr-uint
  "An unsigned integer from `n` CSPRNG bytes, big-endian."
  [n]
  (let [b (random-bytes n)]
    (loop [i 0 acc 0]
      (if (= i n) acc (recur (inc i) (+ (* acc 256) (bit-and (aget b i) 255)))))))

(defn- sr-signed
  "The same, reinterpreted as a signed n-byte two's-complement integer."
  [n]
  (let [u (sr-uint n) half (bit-shift-left 1 (dec (* 8 n)))]
    (if (>= u half) (- u (* 2 half)) u)))

(defn- sr-next-int-bound
  "Uniform in [0, bound). Rejection sampling rather than a bare modulo: over a
  range that is not a multiple of bound, mod makes the low residues more likely,
  which is a real bias in something used to pick tokens and salts."
  [bound]
  (when-not (pos? bound)
    (throw (ex-info "bound must be positive" {:bound bound})))
  (loop []
    (let [u (bit-and (sr-uint 4) 0x7fffffff) r (mod u bound)]
      (if (<= (- u r) (- 2147483648 bound)) r (recur)))))

;; --- X.509 certificates ----------------------------------------------------
(defn- x509-public-key? [x] (and (table? x) (= :jolt.crypto/public-key (tget x :jolt/type))))

(defn certificate-subject
  "Return an X.509 subject in certificate RDN order, as Buddy's X500Name does."
  [cert]
  (when-not (x509/x509-cert? cert)
    (throw (ex-info "Unknown certificate type" {:kind (class cert)})))
  (str/join "," (reverse (x509/split-rdns (tget cert :subject)))))

(defn verify-certificate-signature
  "Verify a parsed X.509 value with a tagged public key or issuer certificate."
  [cert public-key]
  (when-not (x509/x509-cert? cert)
    (throw (ex-info "Unknown certificate type" {:kind (class cert)})))
  (cond
    (x509-public-key? public-key)
    (openssl/x509-verify (tget cert :der) (tget public-key :bytes))

    (x509/x509-cert? public-key)
    (openssl/x509-verify (tget cert :der) (:der (tget public-key :public-key)))

    :else
    (throw (ex-info "Unknown public key type" {:kind (class public-key)}))))

(defn- install-secret-key-specs!
  "javax.crypto.spec.SecretKeySpec / IvParameterSpec: key and IV holders."
  []
  (doseq [nm ["SecretKeySpec" "javax.crypto.spec.SecretKeySpec"]]
    ;; (key algo) or (key off len algo) — the four-arg form keys on a window.
    (__register-class-ctor! nm (fn [key & more]
                                 (let [[bs algo] (if (= 3 (count more))
                                                   [(ba-window key (first more) (second more)) (nth more 2)]
                                                   [(byte-array key) (first more)])]
                                   (doto (tt :jolt.crypto/key)
                                     (tput! :bytes bs)
                                     (tput! :algo (some-> algo str)))))))
  (doseq [nm ["IvParameterSpec" "javax.crypto.spec.IvParameterSpec"]]
    (__register-class-ctor! nm (fn [iv & more]
                                 (doto (tt :jolt.crypto/iv)
                                   (tput! :bytes (if (= 2 (count more))
                                                   (ba-window iv (first more) (second more))
                                                   (byte-array iv)))))))
  (__register-class-methods! :jolt.crypto/key {"getEncoded" (fn [self] (tget self :bytes))
                                               "getAlgorithm" (fn [self] (or (tget self :algo) "AES"))})
  nil)

(defn- install-cipher!
  "javax.crypto.Cipher: getInstance and ENCRYPT_MODE/DECRYPT_MODE, then the
  stateful init/doFinal pair (Java's Cipher is mutable: init sets key, IV and
  mode)."
  []
  (doseq [nm ["Cipher" "javax.crypto.Cipher"]]
    (__register-class-statics! nm {"getInstance" (fn [algo & _] (doto (tt :jolt.crypto/cipher) (tput! :algo (str algo))))
                                   "ENCRYPT_MODE" ENCRYPT-MODE
                                   "DECRYPT_MODE" DECRYPT-MODE}))
  (__register-class-methods! :jolt.crypto/cipher
    {"init" (fn [self mode key & more]
              (tput! self :mode mode)
              (tput! self :key (->ba key))
              (tput! self :iv (if (seq more) (->ba (first more)) (random-bytes 16)))
              nil)
     "doFinal" (fn [self data & more]
                 (let [d (if (= 2 (count more))
                           (ba-window data (first more) (second more))
                           data)]
                   (aes-cbc (= ENCRYPT-MODE (tget self :mode)) (tget self :key) (tget self :iv) d)))
     "getIV" (fn [self] (tget self :iv))
     "getBlockSize" (fn [self] 16)})
  nil)

(defn- install-mac!
  "javax.crypto.Mac"
  []
  (doseq [nm ["Mac" "javax.crypto.Mac"]]
    (__register-class-statics! nm {"getInstance" (fn [algo & _]
                                                   (doto (tt :jolt.crypto/mac)
                                                     (tput! :md (mac-md algo))
                                                     (tput! :acc [])))}))
  (__register-class-methods! :jolt.crypto/mac
    {"init" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "update" (fn [self data & more]
                (tput! self :acc (conj (or (tget self :acc) []) (consume-update-args data more)))
                nil)
     "doFinal" (fn [self & args]
                 (let [[mdf len] (tget self :md)
                       acc (or (tget self :acc) [])
                       ;; doFinal(output, off) writes the mac into the caller's
                       ;; buffer instead of returning a fresh one.
                       output (when (= 2 (count args)) [(first args) (second args)])
                       body (concat-bas (if (and (seq args) (nil? output))
                                          (conj acc (as-ba (first args)))
                                          acc))
                       mac (hmac mdf len (tget self :key) body)]
                   (tput! self :acc [])
                   (if output
                     (do (dotimes [i len] (aset ^bytes (output 0) (+ (output 1) i) (aget mac i)))
                         len)
                     mac)))
     "getMacLength" (fn [self] (let [[_ len] (tget self :md)] len))})
  nil)

(defn- install-message-digest!
  "java.security.MessageDigest"
  []
  (doseq [nm ["MessageDigest" "java.security.MessageDigest"]]
    (__register-class-statics! nm {"getInstance" (fn [algo & _]
                                                   (let [[mdf len] (digest-spec algo)]
                                                     (doto (tt :jolt.crypto/md) (tput! :md mdf) (tput! :len len) (tput! :acc []))))}))
  (__register-class-methods! :jolt.crypto/md
    {"update" (fn [self data & more]
                (tput! self :acc (conj (tget self :acc) (consume-update-args data more)))
                nil)
     "digest" (fn [self & args]
                ;; digest(buf, off, len) is an output overload: it digests the
                ;; accumulated state, writes it into buf at off, and returns the
                ;; digest length (throwing when len is below it).
                (if (= 3 (count args))
                  (let [[buf off len] args
                        dlen (tget self :len)]
                    (when (< len dlen)
                      (throw (ex-info "insufficient space in the output buffer for the digest"
                                      {:len len :digest-length dlen})))
                    (let [d (digest (tget self :md) dlen (concat-bas (tget self :acc)))]
                      (tput! self :acc [])
                      (dotimes [i dlen] (aset ^bytes buf (+ off i) (aget d i)))
                      dlen))
                ;; digest(bytes) is update(bytes)-then-digest on the JVM: the
                ;; accumulated update bytes come FIRST, not instead. Dropping
                ;; them made clj-uuid's namespaced v3/v5 uuids — digest-bytes
                ;; updates with the namespace, digests with the name — hash the
                ;; name alone.
                (let [acc (tget self :acc)
                      body (concat-bas (if (seq args)
                                         (conj acc (as-ba (first args)))
                                         acc))]
                  (tput! self :acc [])
                  (digest (tget self :md) (tget self :len) body))))
     "reset" (fn [self] (tput! self :acc []) nil)})
  nil)

(defn- install-secure-random!
  "java.security.SecureRandom over RAND_bytes (http-client's stub only made a
  table; this fills the buffer for genuine randomness)."
  []
  ;;
  ;; Recent jolt implements this class natively over the OS CSPRNG, and this
  ;; registration overrides it whenever this namespace loads. So the surface here
  ;; has to be the WHOLE surface: when it was just nextBytes/generateSeed, merely
  ;; requiring jolt.crypto for a Cipher took nextInt and nextLong away from a
  ;; program that had them. Keeping it complete also keeps this library working
  ;; on a jolt that has no native SecureRandom.
  (doseq [nm ["SecureRandom" "java.security.SecureRandom"]]
    (__register-class-ctor! nm (fn [& _] (tt :jolt.crypto/secure-random)))
    (__register-class-statics! nm {"getInstance" (fn [& _] (tt :jolt.crypto/secure-random))
                                   "getInstanceStrong" (fn [& _] (tt :jolt.crypto/secure-random))}))
  (__register-class-methods! :jolt.crypto/secure-random
    {"nextBytes" (fn [self buf & _]
                   (let [n (alength buf) r (random-bytes n)]
                     (dotimes [i n] (aset buf i (aget r i)))
                     nil))
     "generateSeed" (fn [self n] (random-bytes n))
     "nextInt" (fn [self & args]
                 (if (seq args)
                   (sr-next-int-bound (first args))
                   (sr-signed 4)))
     "nextLong" (fn [self] (sr-signed 8))
     "nextDouble" (fn [self] (* (bit-and (sr-uint 7) 9007199254740991) (/ 1.0 9007199254740992)))
     "nextFloat" (fn [self] (/ (bit-and (sr-uint 3) 16777215) 16777216.0))
     "nextBoolean" (fn [self] (= 1 (bit-and (sr-uint 1) 1)))
     ;; setSeed supplements entropy on the JVM and never replaces it; with
     ;; RAND_bytes there is nothing to supplement, so it is a no-op.
     "setSeed" (fn [self & _] nil)})
  nil)

(defn- install-key-specs!
  "java.security.spec's holders for a curve name or DER bytes, and the
  PublicKey / PrivateKey they decode to."
  []
  (doseq [[nm tag] [["ECGenParameterSpec" :jolt.crypto/ec-params]
                    ["java.security.spec.ECGenParameterSpec" :jolt.crypto/ec-params]]]
    (__register-class-ctor! nm (fn [curve & _] (doto (tt tag) (tput! :curve (str curve))))))
  (__register-class-methods! :jolt.crypto/ec-params {"getName" (fn [self] (tget self :curve))})

  (doseq [[nm tag] [["X509EncodedKeySpec" :jolt.crypto/x509-spec]
                    ["java.security.spec.X509EncodedKeySpec" :jolt.crypto/x509-spec]
                    ["PKCS8EncodedKeySpec" :jolt.crypto/pkcs8-spec]
                    ["java.security.spec.PKCS8EncodedKeySpec" :jolt.crypto/pkcs8-spec]]]
    (__register-class-ctor! nm (fn [der & _] (doto (tt tag) (tput! :bytes (byte-array der))))))
  (__register-class-methods! :jolt.crypto/x509-spec
    {"getEncoded" (fn [self] (tget self :bytes)) "getFormat" (fn [self] "X.509")})
  (__register-class-methods! :jolt.crypto/pkcs8-spec
    {"getEncoded" (fn [self] (tget self :bytes)) "getFormat" (fn [self] "PKCS#8")})

  ;; PublicKey / PrivateKey. getEncoded is the DER the JVM hands back, which is
  ;; what makes these keys interchangeable with a real JVM's. :algo is set by
  ;; whoever built the key (KeyFactory, KeyPairGenerator); the default keeps
  ;; tables built before RSA existed reporting EC, as they did.
  (__register-class-methods! :jolt.crypto/public-key
    {"getEncoded" (fn [self] (tget self :bytes))
     "getAlgorithm" (fn [self] (or (tget self :algo) "EC"))
     "getFormat" (fn [self] "X.509")})
  (__register-class-methods! :jolt.crypto/private-key
    {"getEncoded" (fn [self] (tget self :bytes))
     "getAlgorithm" (fn [self] (or (tget self :algo) "EC"))
     "getFormat" (fn [self] "PKCS#8")})
  nil)

(defn- keypair-generator
  "KeyPairGenerator.getInstance: a generator holding the JDK's defaults."
  [algo & _]
  (case (str/upper-case (str algo))
    "EC" (doto (tt :jolt.crypto/keypair-gen)
           (tput! :algo "EC") (tput! :curve "secp256r1"))
    ;; the JDK's default RSA size is 2048
    "RSA" (doto (tt :jolt.crypto/keypair-gen)
            (tput! :algo "RSA") (tput! :bits 2048))
    ;; the JDK's EdDSA generator defaults to Ed25519
    "X25519" (doto (tt :jolt.crypto/keypair-gen) (tput! :algo "XDH"))
    ("ED25519" "EDDSA") (doto (tt :jolt.crypto/keypair-gen) (tput! :algo "EdDSA"))
    (throw (ex-info (str "unsupported KeyPairGenerator algorithm: " algo) {:algo algo}))))

(defn- initialize-rsa-generator! [self spec]
  (when (table? spec)
    (throw (ex-info (str "unsupported RSA parameter: " spec) {:spec spec})))
  (let [bits (long spec)]
    (when-not (<= 512 bits 16384)
      (throw (ex-info (str "RSA key size must be between 512 and 16384 bits, got " bits)
                      {:bits bits})))
    (tput! self :bits bits)))

(defn- initialize-ec-generator! [self spec]
  (let [curve (if (and (table? spec) (= :jolt.crypto/ec-params (tget spec :jolt/type)))
                (tget spec :curve)
                (case (long spec)
                  256 "secp256r1" 384 "secp384r1" 521 "secp521r1"
                  (throw (ex-info (str "unsupported EC key size: " spec) {:keysize spec}))))]
    (curve-nid curve)
    (tput! self :curve curve)))

(defn- initialize-keypair-generator!
  "KeyPairGenerator.initialize. initialize(AlgorithmParameterSpec) names the
  curve; initialize(int) gives a key size in bits, which for EC selects the
  P-curve of that size and for RSA is the modulus length. The curve is resolved
  here rather than at generate time because that is where the JDK rejects an
  unknown one."
  [self spec & _]
  (case (tget self :algo)
    ;; Ed25519 has one size: 255 bits, as the JDK takes it
    ("XDH" "EdDSA") (when-not (and (not (table? spec)) (= 255 (long spec)))
              (throw (ex-info (str "unsupported 255-bit key parameter: " spec) {:spec spec})))
    "RSA" (initialize-rsa-generator! self spec)
    (initialize-ec-generator! self spec))
  nil)

(defn- install-keypair-generator!
  "java.security.KeyPairGenerator. Java's is stateful: getInstance picks the
  algorithm, initialize picks the curve or size, generateKeyPair draws a key."
  []
  (doseq [nm ["KeyPairGenerator" "java.security.KeyPairGenerator"]]
    (__register-class-statics! nm {"getInstance" keypair-generator}))
  (__register-class-methods! :jolt.crypto/keypair-gen
    {"initialize" initialize-keypair-generator!
     "generateKeyPair" (fn [self] (generate-keypair-for self))
     ;; genKeyPair is the older spelling of the same method
     "genKeyPair" (fn [self] (generate-keypair-for self))})
  (__register-class-methods! :jolt.crypto/keypair
    {"getPublic" (fn [self] (doto (tt :jolt.crypto/public-key)
                              (tput! :bytes (tget self :public))
                              (tput! :algo (tget self :algo))
                              (tput! :key-type (tget self :key-type))))
     "getPrivate" (fn [self] (doto (tt :jolt.crypto/private-key)
                               (tput! :bytes (tget self :private))
                               (tput! :algo (tget self :algo))
                               (tput! :key-type (tget self :key-type))))})
  nil)

(defn- install-key-factory!
  "java.security.KeyFactory: DER key spec in, key object out."
  []
  ;; Decoding once here means malformed bytes are rejected at generate* time,
  ;; as on the JVM, rather than surfacing later as a mysterious verification
  ;; failure. The decoded key's own OpenSSL type — not the algorithm the factory
  ;; was asked for or a filename — is what the key gets stamped with, and a
  ;; disagreement between the two is an error, as it is on the JVM.
  (doseq [nm ["KeyFactory" "java.security.KeyFactory"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (case (str/upper-case (str algo))
                         "EC" (doto (tt :jolt.crypto/key-factory) (tput! :algo "EC"))
                         "RSA" (doto (tt :jolt.crypto/key-factory) (tput! :algo "RSA"))
                         "DSA" (doto (tt :jolt.crypto/key-factory) (tput! :algo "DSA"))
                         "X25519" (doto (tt :jolt.crypto/key-factory)
                                    (tput! :algo "XDH") (tput! :key-type "X25519"))
                         "ED25519" (doto (tt :jolt.crypto/key-factory)
                                     (tput! :algo "EdDSA") (tput! :key-type "Ed25519"))
                         "EDDSA" (doto (tt :jolt.crypto/key-factory) (tput! :algo "EdDSA"))
                         "ED448" (doto (tt :jolt.crypto/key-factory)
                                   (tput! :algo "EdDSA") (tput! :key-type "Ed448"))
                         (throw (ex-info (str "unsupported KeyFactory algorithm: " algo) {:algo algo}))))}))
  (__register-class-methods! :jolt.crypto/key-factory
    {"generatePublic" (fn [self spec]
                        (let [key (decode-public-key (->ba spec))]
                          (check-key-algo (tget self :algo) (tget key :algo))
                          (check-key-type self key)))
     "generatePrivate" (fn [self spec]
                         (let [key (decode-private-key (->ba spec))]
                           (check-key-algo (tget self :algo) (tget key :algo))
                           (check-key-type self key)))
     "getAlgorithm" (fn [self] (tget self :algo))})
  nil)

(defn- derive-x25519 [private-key public-key]
  (with-der-key lc/c-d2i-privkey (->ba private-key)
    (fn [priv]
      (with-der-key lc/c-d2i-pubkey (->ba public-key)
        (fn [pub]
          (let [ctx (lc/c-pkey-ctx-new priv ffi/null)]
            (when (ffi/null? ctx) (throw (ex-info "X25519 context setup failed" {})))
            (try
              (when-not (and (= 1 (lc/c-derive-init ctx)) (= 1 (lc/c-derive-peer ctx pub)))
                (throw (ex-info "X25519 peer setup failed" {})))
              (let [out (ffi/alloc 32) size (ffi/alloc ptr-size)]
                (try
                  (ffi/write size :size_t 32 0)
                  (when-not (and (= 1 (lc/c-derive ctx out size)) (= 32 (ffi/read size :size_t)))
                    (throw (ex-info "X25519 key agreement failed" {})))
                  (ffi/read-array out 32)
                  (finally (ffi/free size) (ffi/free out))))
              (finally (lc/c-pkey-ctx-free ctx)))))))))

(defn- install-key-agreement! []
  (doseq [nm ["KeyAgreement" "javax.crypto.KeyAgreement"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo]
                       (when-not (= "X25519" (str/upper-case algo))
                         (throw (ex-info "Unsupported KeyAgreement algorithm" {:algo algo})))
                       (tt :jolt.crypto/key-agreement))}))
  (__register-class-methods! :jolt.crypto/key-agreement
    {"getAlgorithm" (fn [_] "X25519")
     "init" (fn [self key]
              (when-not (and (= :jolt.crypto/private-key (tget key :jolt/type))
                             (= "X25519" (key-type key)))
                (throw (ex-info "Expected X25519 private key" {})))
              (tput! self :private key)
              (tput! self :secret nil)
              nil)
     "doPhase" (fn [self peer last-phase]
                 (when-not (and (tget self :private) (nil? (tget self :secret))
                                last-phase (= :jolt.crypto/public-key (tget peer :jolt/type))
                                (= "X25519" (key-type peer)))
                   (throw (ex-info "Expected a final X25519 phase with a public key" {})))
                 (tput! self :secret (derive-x25519 (tget self :private) peer))
                 nil)
     "generateSecret" (fn [self]
                        (let [secret (tget self :secret)]
                          (when-not secret (throw (ex-info "X25519 phase is incomplete" {})))
                          (tput! self :secret nil)
                          secret))}))

(defn- install-signature!
  "java.security.Signature, stateful like Cipher: init picks key and
  direction, update accumulates, sign/verify consume and reset."
  []
  (doseq [nm ["Signature" "java.security.Signature"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (let [[md key-algo options] (signature-spec algo)]
                         (doto (tt :jolt.crypto/signature)
                           (tput! :md md)
                           (tput! :key-algo key-algo)
                           (tput! :options options)
                           (tput! :algo (str algo))
                           (tput! :acc []))))}))
  (__register-class-methods! :jolt.crypto/signature
    {"initSign" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "initVerify" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "update" (fn [self data & more]
                (tput! self :acc (conj (tget self :acc) (consume-update-args data more)))
                nil)
     "sign" (fn [self & _]
              (let [body (concat-bas (tget self :acc))]
                (tput! self :acc [])
                (pkey-sign (tget self :md) (tget self :key) body
                           (tget self :key-algo) (tget self :options))))
     "verify" (fn [self sig & more]
                (let [body (concat-bas (tget self :acc))
                      sig (if (= 2 (count more)) (ba-window sig (first more) (second more)) sig)]
                  (tput! self :acc [])
                  (pkey-verify (tget self :md) (tget self :key) body sig
                               (tget self :key-algo) (tget self :options))))
     "getAlgorithm" (fn [self] (tget self :algo))})
  nil)

(defn install!
  "Register the JDK crypto classes this library provides."
  []
  (install-secret-key-specs!)
  (install-cipher!)
  (install-mac!)
  (install-message-digest!)
  (install-secure-random!)
  (install-key-specs!)
  (install-keypair-generator!)
  (install-key-factory!)
  (install-key-agreement!)
  (install-signature!)
  (x509/install!)
  nil)

(install!)
