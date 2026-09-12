(ns jolt.crypto
  "Symmetric crypto for Jolt, bound to the system OpenSSL (libcrypto) through
  jolt.ffi, and exposed as the small slice of the `javax.crypto` / `java.security`
  surface that real Clojure libraries touch:

    Cipher        AES/CBC/PKCS5Padding (128/192/256, key length picks the variant)
    Mac           HmacSHA512 / HmacSHA384 / HmacSHA256 / HmacSHA1
    MessageDigest SHA-512 / SHA-384 / SHA-256 / SHA-224 / SHA-1 / MD5
    SecureRandom  RAND_bytes
    SecretKeySpec / IvParameterSpec   key + IV holders
    KeyPairGenerator / KeyFactory / Signature   EC over the NIST P-curves and
                  RSA, with X509EncodedKeySpec / PKCS8EncodedKeySpec /
                  ECGenParameterSpec
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
            [clojure.string :as str]))

;; --- OpenSSL (libcrypto) bindings -------------------------------------------
(ffi/defcfn c-rand     "RAND_bytes"          [:pointer :int] :int)
(ffi/defcfn c-aes128   "EVP_aes_128_cbc"     [] :pointer)
(ffi/defcfn c-aes192   "EVP_aes_192_cbc"     [] :pointer)
(ffi/defcfn c-aes256   "EVP_aes_256_cbc"     [] :pointer)
(ffi/defcfn c-md5      "EVP_md5"             [] :pointer)
(ffi/defcfn c-sha1     "EVP_sha1"            [] :pointer)
(ffi/defcfn c-sha224   "EVP_sha224"          [] :pointer)
(ffi/defcfn c-sha256   "EVP_sha256"          [] :pointer)
(ffi/defcfn c-sha384   "EVP_sha384"          [] :pointer)
(ffi/defcfn c-sha512   "EVP_sha512"          [] :pointer)
(ffi/defcfn c-ctx-new  "EVP_CIPHER_CTX_new"  [] :pointer)
(ffi/defcfn c-ctx-free "EVP_CIPHER_CTX_free" [:pointer] :void)
(ffi/defcfn c-enc-init "EVP_EncryptInit_ex"  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-enc-upd  "EVP_EncryptUpdate"   [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-enc-fin  "EVP_EncryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-dec-init "EVP_DecryptInit_ex"  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dec-upd  "EVP_DecryptUpdate"   [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-dec-fin  "EVP_DecryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-hmac     "HMAC"   [:pointer :pointer :int :pointer :size_t :pointer :pointer] :pointer)
(ffi/defcfn c-digest   "EVP_Digest" [:pointer :size_t :pointer :pointer :pointer :pointer] :int)

;; EC and RSA keys, ECDSA/RSASSA-PKCS1-v1_5. EVP_EC_gen is a macro rather
;; than an exported symbol, so EC keygen goes through EC_KEY and is then
;; wrapped in an EVP_PKEY for encoding and signing; RSA keygen goes through
;; RSA_new + RSA_generate_key_ex (EVP_PKEY_CTX-based RSA gen needs
;; EVP_PKEY_CTX_new_id, which is fine too but longer). i2d_*/d2i_* are the DER
;; codecs: i2d_PUBKEY is X.509 SubjectPublicKeyInfo (what PublicKey.getEncoded
;; returns) and EVP_PKEY2PKCS8 + i2d_PKCS8_PRIV_KEY_INFO is PKCS#8
;; PrivateKeyInfo (PrivateKey.getEncoded). d2i_AutoPrivateKey reads either
;; algorithm's PKCS#8, and the EVP_Digest* calls in pkey-sign/pkey-verify are
;; algorithm-agnostic — the algorithm is whatever the key is.
(ffi/defcfn c-ec-new-curve "EC_KEY_new_by_curve_name" [:int] :pointer)
(ffi/defcfn c-ec-gen       "EC_KEY_generate_key"      [:pointer] :int)
(ffi/defcfn c-ec-free      "EC_KEY_free"              [:pointer] :void)
(ffi/defcfn c-pkey-new     "EVP_PKEY_new"             [] :pointer)
(ffi/defcfn c-pkey-set-ec  "EVP_PKEY_set1_EC_KEY"     [:pointer :pointer] :int)
(ffi/defcfn c-pkey-free    "EVP_PKEY_free"            [:pointer] :void)
(ffi/defcfn c-i2d-pubkey   "i2d_PUBKEY"               [:pointer :pointer] :int)
(ffi/defcfn c-d2i-pubkey   "d2i_PUBKEY"               [:pointer :pointer :long] :pointer)
(ffi/defcfn c-pkey->p8     "EVP_PKEY2PKCS8"           [:pointer] :pointer)
(ffi/defcfn c-i2d-p8       "i2d_PKCS8_PRIV_KEY_INFO"  [:pointer :pointer] :int)
(ffi/defcfn c-p8-free      "PKCS8_PRIV_KEY_INFO_free" [:pointer] :void)
(ffi/defcfn c-d2i-privkey  "d2i_AutoPrivateKey"       [:pointer :pointer :long] :pointer)
(ffi/defcfn c-md-ctx-new   "EVP_MD_CTX_new"           [] :pointer)
(ffi/defcfn c-md-ctx-free  "EVP_MD_CTX_free"          [:pointer] :void)
(ffi/defcfn c-dgst-sign-init   "EVP_DigestSignInit"   [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dgst-sign        "EVP_DigestSign"       [:pointer :pointer :pointer :pointer :size_t] :int)
(ffi/defcfn c-dgst-verify-init "EVP_DigestVerifyInit" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dgst-verify      "EVP_DigestVerify"     [:pointer :pointer :size_t :pointer :size_t] :int)

;; RSA keygen. RSA_generate_key_ex takes the public exponent as a BIGNUM, so a
;; BN_new/BN_set_word pair sets the usual 65537 (F4) before the call.
(ffi/defcfn c-rsa-new      "RSA_new"             [] :pointer)
(ffi/defcfn c-rsa-gen      "RSA_generate_key_ex" [:pointer :int :pointer :pointer] :int)
(ffi/defcfn c-rsa-free     "RSA_free"            [:pointer] :void)
(ffi/defcfn c-bn-new       "BN_new"              [] :pointer)
(ffi/defcfn c-bn-set-word  "BN_set_word"         [:pointer :ulong] :int)
(ffi/defcfn c-bn-free      "BN_free"             [:pointer] :void)
(ffi/defcfn c-pkey-set-rsa "EVP_PKEY_set1_RSA"   [:pointer :pointer] :int)

;; What a parsed key actually is. EVP_PKEY_base_id is a real function in 1.1 but
;; a macro for EVP_PKEY_get_base_id in 3, so neither spelling resolves on both;
;; EVP_PKEY_get0_* are exported functions in either. A miss pushes
;; EVP_R_EXPECTING_A_* onto the thread's error queue, which nothing here reads,
;; so clear it rather than let it accumulate.
(ffi/defcfn c-pkey-get0-ec  "EVP_PKEY_get0_EC_KEY" [:pointer] :pointer)
(ffi/defcfn c-pkey-get0-rsa "EVP_PKEY_get0_RSA"    [:pointer] :pointer)
(ffi/defcfn c-err-clear     "ERR_clear_error"      []         :void)

;; X.509 certificates. A certificate is parsed from PEM (PEM_read_bio_X509) or
;; DER (d2i_X509) into an X509 that lives only for the duration of the parse:
;; every field a program can ask for is read out then and stored on the shim
;; object, so nothing native outlives the call and the value travels like data.
;; The names print through X509_NAME_print_ex, which spells RFC 2253 exactly as
;; X500Principal.getName does. Times come out as struct tm (ASN1_TIME_to_tm) and
;; the serial as a BIGNUM hex string; i2d_X509 / i2d_PUBKEY are the DER
;; encodings getEncoded answers with, byte-identical to the JVM's.
(ffi/defcfn c-bio-new-mem-buf  "BIO_new_mem_buf"         [:pointer :int] :pointer)
(ffi/defcfn c-bio-new          "BIO_new"                 [:pointer] :pointer)
(ffi/defcfn c-bio-s-mem        "BIO_s_mem"               [] :pointer)
(ffi/defcfn c-bio-read         "BIO_read"                [:pointer :pointer :int] :int)
(ffi/defcfn c-bio-free         "BIO_free"                [:pointer] :int)
(ffi/defcfn c-pem-read-x509    "PEM_read_bio_X509"       [:pointer :pointer :pointer :pointer] :pointer)
(ffi/defcfn c-d2i-x509         "d2i_X509"                [:pointer :pointer :long] :pointer)
(ffi/defcfn c-i2d-x509         "i2d_X509"                [:pointer :pointer] :int)
(ffi/defcfn c-x509-free        "X509_free"               [:pointer] :void)
(ffi/defcfn c-x509-subject     "X509_get_subject_name"   [:pointer] :pointer)
(ffi/defcfn c-x509-issuer      "X509_get_issuer_name"    [:pointer] :pointer)
(ffi/defcfn c-name-print-ex    "X509_NAME_print_ex"      [:pointer :pointer :int :ulong] :int)
(ffi/defcfn c-x509-not-before  "X509_get0_notBefore"     [:pointer] :pointer)
(ffi/defcfn c-x509-not-after   "X509_get0_notAfter"      [:pointer] :pointer)
(ffi/defcfn c-asn1-time-to-tm  "ASN1_TIME_to_tm"         [:pointer :pointer] :int)
(ffi/defcfn c-x509-serial      "X509_get_serialNumber"   [:pointer] :pointer)
(ffi/defcfn c-asn1-int-to-bn   "ASN1_INTEGER_to_BN"      [:pointer :pointer] :pointer)
(ffi/defcfn c-bn-bn2hex        "BN_bn2hex"               [:pointer] :pointer)
(ffi/defcfn c-crypto-free      "CRYPTO_free"             [:pointer :pointer :int] :void)
(ffi/defcfn c-x509-version     "X509_get_version"        [:pointer] :long)
(ffi/defcfn c-x509-sig-nid     "X509_get_signature_nid"  [:pointer] :int)
(ffi/defcfn c-obj-nid2obj      "OBJ_nid2obj"             [:int] :pointer)
(ffi/defcfn c-obj-obj2nid      "OBJ_obj2nid"             [:pointer] :int)
(ffi/defcfn c-obj-obj2txt      "OBJ_obj2txt"             [:pointer :int :pointer :int] :int)
(ffi/defcfn c-obj-nid2sn       "OBJ_nid2sn"              [:int] :pointer)
(ffi/defcfn c-x509-get-pubkey  "X509_get_pubkey"         [:pointer] :pointer)
(ffi/defcfn c-x509-get-spki    "X509_get_X509_PUBKEY"    [:pointer] :pointer)
(ffi/defcfn c-spki-get0-param  "X509_PUBKEY_get0_param"  [:pointer :pointer :pointer :pointer :pointer] :int)

;; --- helpers ----------------------------------------------------------------
(defn- tt [tag] (jolt.host/tagged-table tag))
(defn- tget [t k] (jolt.host/ref-get t k))
(defn- tput! [t k v] (jolt.host/ref-put! t k v))
(defn- table? [x] (jolt.host/table? x))

;; binary bytes only — these objects never carry text, so coerce through
;; byte-array (a seq/byte-array round-trips; never the UTF-8 read/write-bytes).
(defn- ->ba [x]
  (cond
    (and (table? x) (#{:jolt.crypto/key :jolt.crypto/iv
                       :jolt.crypto/public-key :jolt.crypto/private-key
                       :jolt.crypto/x509-spec :jolt.crypto/pkcs8-spec}
                     (tget x :jolt/type)))
    (tget x :bytes)
    :else (byte-array x)))

(defn- as-ba [x]
  ;; Native calls only read their input while the call is in progress. Avoid
  ;; rebuilding an existing byte array through its boxed sequence in that case.
  (if (bytes? x) x (->ba x)))

(defn- snapshot-ba [x]
  ;; Stateful update methods must consume the caller's bytes when update is
  ;; called, not retain an array the caller can mutate before digest/sign.
  (aclone (as-ba x)))

(defn- concat-bas [bas]
  "Join byte arrays with bulk copies."
  (let [total (reduce + 0 (map alength bas))
        out (byte-array total)]
    (loop [off 0 remaining bas]
      (if-let [src (first remaining)]
        (do
          (System/arraycopy src 0 out off (alength src))
          (recur (+ off (alength src)) (rest remaining)))
        out))))

(defn- with-ptrs
  "Alloc a C buffer per byte-array in `bas`, copy each in, run (f ptrs…), free all."
  [bas f]
  (let [ptrs (mapv (fn [ba] (let [n (max 1 (alength ba)) p (ffi/alloc n)]
                              (ffi/write-array p ba) p))
                   bas)]
    (try (apply f ptrs) (finally (doseq [p ptrs] (ffi/free p))))))

(defn- evp-cipher-for [keylen]
  (case keylen 16 (c-aes128) 24 (c-aes192) 32 (c-aes256)
    (throw (ex-info (str "AES key must be 16/24/32 bytes, got " keylen) {:keylen keylen}))))

;; --- AES-CBC (PKCS5/PKCS7 padding is EVP's CBC default) ---------------------
(defn aes-cbc [encrypt? key iv data]
  (let [key (as-ba key) iv (as-ba iv) data (as-ba data)
        ctx (c-ctx-new) ciph (evp-cipher-for (alength key)) inlen (alength data)]
    (with-ptrs [key iv data]
      (fn [keyp ivp inp]
        (let [outp (ffi/alloc (+ inlen 32)) outlp (ffi/alloc 4)
              [init upd fin] (if encrypt? [c-enc-init c-enc-upd c-enc-fin]
                                          [c-dec-init c-dec-upd c-dec-fin])]
          (try
            (when (not= 1 (init ctx ciph ffi/null keyp ivp)) (throw (ex-info "cipher init failed" {})))
            (when (not= 1 (upd ctx outp outlp inp inlen)) (throw (ex-info "cipher update failed" {})))
            (let [n1 (ffi/read outlp :int)]
              (when (not= 1 (fin ctx (+ outp n1) outlp))
                (throw (ex-info (if encrypt? "cipher final failed" "bad padding / wrong key") {})))
              (ffi/read-array outp (+ n1 (ffi/read outlp :int))))
            (finally (c-ctx-free ctx) (ffi/free outp) (ffi/free outlp))))))))

;; --- HMAC -------------------------------------------------------------------
(defn hmac [md-fn outlen key data]
  (let [key (as-ba key) data (as-ba data) kl (alength key) dl (alength data)]
    (with-ptrs [key data]
      (fn [kp dp]
        (let [mdp (ffi/alloc 64)]
          (try (c-hmac (md-fn) kp kl dp dl mdp ffi/null) (ffi/read-array mdp outlen)
               (finally (ffi/free mdp))))))))

;; --- digest -----------------------------------------------------------------
(defn digest [md-fn outlen data]
  (let [data (as-ba data) dl (alength data)]
    (with-ptrs [data]
      (fn [dp]
        (let [mdp (ffi/alloc 64) lenp (ffi/alloc 4)]
          (try (when (not= 1 (c-digest dp dl mdp lenp (md-fn) ffi/null))
                 (throw (ex-info "digest failed" {})))
               (ffi/read-array mdp outlen)
               (finally (ffi/free mdp) (ffi/free lenp))))))))

(defn random-bytes [n]
  (let [p (ffi/alloc (max 1 n))]
    (try (when (not= 1 (c-rand p n)) (throw (ex-info "RAND_bytes failed" {})))
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

(def ^:private ptr-size (ffi/sizeof :pointer))

(defn- der-out
  "Run an i2d_* encoder over obj and return the DER bytes. Called once with a
  null output pointer it reports the length, which is how the buffer gets sized
  without needing OPENSSL_free (a macro, so not callable through the FFI)."
  [i2d-fn obj]
  (let [len (i2d-fn obj ffi/null)]
    (when (<= len 0) (throw (ex-info "DER encode failed" {:len len})))
    (let [buf (ffi/alloc len) holder (ffi/alloc ptr-size)]
      (try
        (ffi/write holder :pointer buf 0)
        (let [n (i2d-fn obj holder)]
          (when (<= n 0) (throw (ex-info "DER encode failed" {:len n})))
          (ffi/read-array buf n))
        (finally (ffi/free buf) (ffi/free holder))))))

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
        (try (f pkey) (finally (c-pkey-free pkey))))
      (finally (ffi/free buf) (ffi/free holder)))))

(defn- pkey-algo
  "The algorithm a parsed EVP_PKEY actually is: \"EC\", \"RSA\", or nil for
  anything else — the EVP_Digest* path is algorithm-agnostic, so a key type
  this namespace does not name is not by itself a reason to refuse."
  [pkey]
  (let [algo (cond
               (not (ffi/null? (c-pkey-get0-ec pkey)))  "EC"
               (not (ffi/null? (c-pkey-get0-rsa pkey))) "RSA")]
    (c-err-clear)
    algo))

(defn- check-key-algo
  "Refuse a key that is not the algorithm the caller asked for, as the JDK does
  rather than quietly signing with whatever the key happens to be. Only a
  positive disagreement is an error: either side being unknown lets it pass."
  [want got]
  (when (and want got (not= want got))
    (throw (ex-info (str "key algorithm mismatch: expected " want ", got " got)
                    {:expected want :actual got})))
  got)

(defn generate-ec-keypair
  "Generate an EC keypair on `curve`. Returns {:public <X.509 DER> :private <PKCS#8 DER>},
  the same two encodings the JVM's getEncoded hands back."
  [curve]
  (let [eck (c-ec-new-curve (curve-nid curve))]
    (when (ffi/null? eck) (throw (ex-info (str "EC key setup failed for curve " curve) {:curve curve})))
    (try
      (when (not= 1 (c-ec-gen eck)) (throw (ex-info "EC key generation failed" {:curve curve})))
      (let [pkey (c-pkey-new)]
        (try
          (when (not= 1 (c-pkey-set-ec pkey eck)) (throw (ex-info "EC key wrap failed" {})))
          (let [p8 (c-pkey->p8 pkey)]
            (when (ffi/null? p8) (throw (ex-info "PKCS#8 conversion failed" {})))
            (try {:public (der-out c-i2d-pubkey pkey) :private (der-out c-i2d-p8 p8)}
                 (finally (c-p8-free p8))))
          (finally (c-pkey-free pkey))))
      (finally (c-ec-free eck)))))

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
  (let [rsa (c-rsa-new)
        e (c-bn-new)]
    (when (ffi/null? rsa) (throw (ex-info "RSA key setup failed" {})))
    (when (ffi/null? e) (throw (ex-info "BN setup failed" {})))
    (try
      (when (not= 1 (c-bn-set-word e 65537)) (throw (ex-info "BN_set_word failed" {})))
      (when (not= 1 (c-rsa-gen rsa bits e ffi/null))
        (throw (ex-info (str "RSA key generation failed for " bits " bits") {:bits bits})))
      (let [pkey (c-pkey-new)]
        (try
          (when (not= 1 (c-pkey-set-rsa pkey rsa)) (throw (ex-info "RSA key wrap failed" {})))
          (let [p8 (c-pkey->p8 pkey)]
            (when (ffi/null? p8) (throw (ex-info "PKCS#8 conversion failed" {})))
            (try {:public (der-out c-i2d-pubkey pkey) :private (der-out c-i2d-p8 p8)}
                 (finally (c-p8-free p8))))
          (finally (c-pkey-free pkey))))
      (finally (c-bn-free e) (c-rsa-free rsa)))))

(defn- generate-keypair-for
  "Draw a keypair from a KeyPairGenerator shim's state: {:public :private
  :algo}, ready for the keypair shim."
  [self]
  (let [{:keys [public private]} (if (= "RSA" (tget self :algo))
                                   (generate-rsa-keypair (tget self :bits))
                                   (generate-ec-keypair (tget self :curve)))]
    (doto (tt :jolt.crypto/keypair)
      (tput! :public public) (tput! :private private) (tput! :algo (tget self :algo)))))

(defn pkey-sign
  "Sign `data` with a PKCS#8 DER private key, digesting with md-fn. The result
  is what Signature.sign returns on the JVM for that key: a DER-encoded ECDSA
  SEQUENCE of r and s for an EC key, the raw PKCS#1 v1.5 ciphertext for RSA.
  EVP picks the primitive from the key itself, so the same call serves both —
  and so `want-algo`, when given, is what stops a key of the other algorithm
  producing a signature the named algorithm did not ask for."
  ([md-fn priv-der data] (pkey-sign md-fn priv-der data nil))
  ([md-fn priv-der data want-algo]
   (with-der-key c-d2i-privkey priv-der
     (fn [pkey]
       (check-key-algo want-algo (pkey-algo pkey))
       (let [data (as-ba data) dn (alength data)
             ctx (c-md-ctx-new) dp (ffi/alloc (max 1 dn)) lenp (ffi/alloc 8)]
         (try
           (ffi/write-array dp data)
           (when (not= 1 (c-dgst-sign-init ctx ffi/null (md-fn) ffi/null pkey))
             (throw (ex-info "signature init failed" {})))
           ;; a null signature buffer asks for the maximum size rather than signing
           (ffi/write lenp :size_t 0 0)
           (when (not= 1 (c-dgst-sign ctx ffi/null lenp dp dn))
             (throw (ex-info "signature sizing failed" {})))
           (let [sigp (ffi/alloc (ffi/read lenp :size_t))]
             (try
               (when (not= 1 (c-dgst-sign ctx sigp lenp dp dn))
                 (throw (ex-info "signing failed" {})))
               (ffi/read-array sigp (ffi/read lenp :size_t))
               (finally (ffi/free sigp))))
           (finally (c-md-ctx-free ctx) (ffi/free dp) (ffi/free lenp))))))))

(defn pkey-verify
  "Verify a signature over `data` against an X.509 DER public key, digesting
  with md-fn. The signature format is the key algorithm's (DER ECDSA r/s, raw
  PKCS#1 v1.5 RSA); `want-algo`, when given, holds the key to that algorithm."
  ([md-fn pub-der data sig] (pkey-verify md-fn pub-der data sig nil))
  ([md-fn pub-der data sig want-algo]
   (with-der-key c-d2i-pubkey pub-der
     (fn [pkey]
       (check-key-algo want-algo (pkey-algo pkey))
       (let [data (as-ba data) sig (as-ba sig) dn (alength data) sn (alength sig)
             ctx (c-md-ctx-new) dp (ffi/alloc (max 1 dn)) sp (ffi/alloc (max 1 sn))]
         (try
           (ffi/write-array dp data)
           (ffi/write-array sp sig)
           (when (not= 1 (c-dgst-verify-init ctx ffi/null (md-fn) ffi/null pkey))
             (throw (ex-info "verification init failed" {})))
           ;; a bad signature is a false, not a throw: EVP reports both the same way
           (= 1 (c-dgst-verify ctx sp sn dp dn))
           (finally (c-md-ctx-free ctx) (ffi/free dp) (ffi/free sp))))))))

;; --- X.509 certificates ------------------------------------------------------
(defn- with-mem-bio
  "A memory BIO over `bytes`, run (f bio), freed."
  [bytes f]
  (let [bytes (as-ba bytes) n (alength bytes) buf (ffi/alloc (max 1 n))]
    (try
      (ffi/write-array buf bytes)
      (let [bio (c-bio-new-mem-buf buf n)]
        (when (ffi/null? bio) (throw (ex-info "BIO_new_mem_buf failed" {})))
        (try (f bio) (finally (c-bio-free bio))))
      (finally (ffi/free buf)))))

(defn- bio-mem-string
  "Run (f bio) against a fresh memory BIO, answer what was written to it as a
  string."
  [f]
  (let [bio (c-bio-new (c-bio-s-mem))]
    (when (ffi/null? bio) (throw (ex-info "BIO_new failed" {})))
    (try
      (f bio)
      (let [chunk 4096 buf (ffi/alloc chunk)]
        (try
          (loop [parts []]
            (let [n (c-bio-read bio buf chunk)]
              (if (pos? n)
                (recur (conj parts (ffi/read-array buf n)))
                (String. (concat-bas parts) "UTF-8"))))
          (finally (ffi/free buf))))
      (finally (c-bio-free bio)))))

;; XN_FLAG_RFC2253: what X500Principal.getName() spells — reversed RDN order,
;; comma-separated, short attribute names, RFC 2253 escaping.
(def ^:private xn-flag-rfc2253 0x1110317)

(defn- x509-name-rfc2253 [name]
  (bio-mem-string (fn [bio] (c-name-print-ex bio name 0 xn-flag-rfc2253))))

;; The RFC 1779-flavoured spelling X500Name.toString (getSubjectDN().getName())
;; answers: the same RDNs with ", " between them. Split on the unescaped commas.
(defn- split-rdns [s]
  (let [n (count s)]
    (loop [i 0 start 0 acc []]
      (cond (>= i n) (conj acc (subs s start))
            (= \\ (nth s i)) (recur (+ i 2) start acc)
            (= \, (nth s i)) (recur (inc i) (inc i) (conj acc (subs s start i)))
            :else (recur (inc i) start acc)))))
(defn- rfc2253->rfc1779 [s]
  (str/join ", " (split-rdns s)))

(defn- days-from-civil
  "Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
  algorithm)."
  [y m d]
  (let [y (if (<= m 2) (dec y) y)
        era (quot (if (>= y 0) y (- y 399)) 400)
        yoe (- y (* era 400))
        doy (+ (quot (+ (* 153 (+ m (if (> m 2) -3 9))) 2) 5) (dec d))
        doe (+ (* yoe 365) (quot yoe 4) (- (quot yoe 100)) doy)]
    (+ (* era 146097) doe -719468)))

(defn- asn1-time->epoch-ms
  "The instant an ASN1_TIME names, as epoch milliseconds. Read as a struct tm —
  the first six ints are tm_sec .. tm_year on every platform — and folded to a
  day count; ASN1 times are UTC by definition."
  [t]
  (let [tm (ffi/alloc 64)]
    (try
      (when (not= 1 (c-asn1-time-to-tm t tm))
        (throw (ex-info "ASN1_TIME_to_tm failed" {})))
      (let [sec (ffi/read tm :int 0) min (ffi/read tm :int 4) hour (ffi/read tm :int 8)
            mday (ffi/read tm :int 12) mon (ffi/read tm :int 16) year (ffi/read tm :int 20)]
        (* 1000 (+ (* 86400 (days-from-civil (+ 1900 year) (inc mon) mday))
                   (* 3600 hour) (* 60 min) sec)))
      (finally (ffi/free tm)))))

(defn- serial-bigint [x509]
  (let [bn (c-asn1-int-to-bn (c-x509-serial x509) ffi/null)]
    (when (ffi/null? bn) (throw (ex-info "ASN1_INTEGER_to_BN failed" {})))
    (try
      (let [hex (c-bn-bn2hex bn)]
        (try (BigInteger. (ffi/ptr->string hex) 16)
             (finally (c-crypto-free hex ffi/null 0))))
      (finally (c-bn-free bn)))))

(defn- obj-oid
  "An ASN1_OBJECT's dotted OID."
  [obj]
  (let [buf (ffi/alloc 128)]
    (try
      (c-obj-obj2txt buf 128 obj 1)
      (ffi/ptr->string buf)
      (finally (ffi/free buf)))))

;; The JVM's names for the signature algorithms it knows; anything else is
;; reported as its OID, as X509Certificate.getSigAlgName does.
(def ^:private sig-alg-names
  {"1.2.840.10045.4.3.2" "SHA256withECDSA" "1.2.840.10045.4.3.3" "SHA384withECDSA"
   "1.2.840.10045.4.3.4" "SHA512withECDSA" "1.2.840.10045.4.3.1" "SHA224withECDSA"
   "1.2.840.10045.4.1" "SHA1withECDSA"
   "1.2.840.113549.1.1.11" "SHA256withRSA" "1.2.840.113549.1.1.12" "SHA384withRSA"
   "1.2.840.113549.1.1.13" "SHA512withRSA" "1.2.840.113549.1.1.14" "SHA224withRSA"
   "1.2.840.113549.1.1.5" "SHA1withRSA" "1.2.840.113549.1.1.4" "MD5withRSA"
   "1.2.840.113549.1.1.10" "RSASSA-PSS"
   "1.3.101.112" "Ed25519" "1.3.101.113" "Ed448"
   "2.16.840.1.101.3.4.3.2" "SHA256withDSA" "1.2.840.10040.4.3" "SHA1withDSA"})

;; PublicKey.getAlgorithm for a SubjectPublicKeyInfo algorithm's short name
(def ^:private key-alg-names
  {"id-ecPublicKey" "EC" "rsaEncryption" "RSA" "rsassaPss" "RSASSA-PSS"
   "dsaEncryption" "DSA" "ED25519" "EdDSA" "ED448" "EdDSA" "X25519" "XDH" "X448" "XDH"})

(defn- x509-public-key
  "{:algorithm :der} for the certificate's subject public key."
  [x509]
  (let [pkey (c-x509-get-pubkey x509)]
    (when (ffi/null? pkey) (throw (ex-info "X509_get_pubkey failed" {})))
    (try
      (let [holder (ffi/alloc ptr-size)]
        (try
          (ffi/write holder :pointer ffi/null 0)
          (c-spki-get0-param holder ffi/null ffi/null ffi/null (c-x509-get-spki x509))
          (let [alg (ffi/read holder :pointer 0)
                sn (if (ffi/null? alg) "" (ffi/ptr->string (c-obj-nid2sn (c-obj-obj2nid alg))))]
            {:algorithm (get key-alg-names sn sn)
             :der (der-out c-i2d-pubkey pkey)})
          (finally (ffi/free holder))))
      (finally (c-pkey-free pkey)))))

(defn- x509-fields
  "Everything the shim answers, read off a live X509."
  [x509]
  {:der (der-out c-i2d-x509 x509)
   :subject (x509-name-rfc2253 (c-x509-subject x509))
   :issuer (x509-name-rfc2253 (c-x509-issuer x509))
   :not-before (asn1-time->epoch-ms (c-x509-not-before x509))
   :not-after (asn1-time->epoch-ms (c-x509-not-after x509))
   :serial (serial-bigint x509)
   :version (inc (c-x509-version x509))
   :sig-alg-oid (obj-oid (c-obj-nid2obj (c-x509-sig-nid x509)))
   :public-key (x509-public-key x509)})

(defn- pem? [bytes]
  (let [n (min 64 (alength bytes))]
    (str/includes? (String. bytes 0 n "UTF-8") "-----BEGIN")))

(defn- certificate-exception [msg]
  (jolt.host/throwable "java.security.cert.CertificateException" msg))

(defn parse-x509
  "Parse every certificate in `bytes` — one DER certificate, or a PEM file
  holding any number — into field maps (see x509-fields). Throws
  java.security.cert.CertificateException on input that holds none."
  [bytes]
  (let [bytes (as-ba bytes)
        certs (if (and (pos? (alength bytes)) (pem? bytes))
                (with-mem-bio bytes
                  (fn [bio]
                    (loop [acc []]
                      (let [x (c-pem-read-x509 bio ffi/null ffi/null ffi/null)]
                        (if (ffi/null? x)
                          acc
                          (recur (conj acc (try (x509-fields x) (finally (c-x509-free x))))))))))
                (let [n (alength bytes) buf (ffi/alloc (max 1 n)) holder (ffi/alloc ptr-size)]
                  (try
                    (ffi/write-array buf bytes)
                    (ffi/write holder :pointer buf 0)
                    (let [x (c-d2i-x509 ffi/null holder n)]
                      (if (ffi/null? x)
                        []
                        [(try (x509-fields x) (finally (c-x509-free x)))]))
                    (finally (ffi/free buf) (ffi/free holder)))))]
    (when (empty? certs)
      ;; the JVM's wording for input it finds no certificate in
      (throw (certificate-exception "Could not parse certificate: java.io.IOException: Empty input")))
    certs))

;; --- algorithm name -> primitive --------------------------------------------
(defn- mac-md [algo]
  (case (str algo) ("HmacSHA512" "HMACSHA512") [c-sha512 64] ("HmacSHA384" "HMACSHA384") [c-sha384 48]
    ("HmacSHA256" "HMACSHA256") [c-sha256 32] ("HmacSHA1" "HMACSHA1") [c-sha1 20]
    (throw (ex-info (str "unsupported Mac algorithm: " algo) {:algo algo}))))
;; SHA256withECDSA, SHA256withRSA and friends -> [digest, key algorithm]. The
;; JVM spells these without separators and case-insensitively in practice, so
;; match on the upcased form. EVP takes the primitive from the key rather than
;; the name, so the second half is what holds a key to the algorithm it names.
(defn- signature-spec [algo]
  (case (str/upper-case (str algo))
    "SHA512WITHECDSA" [c-sha512 "EC"]
    "SHA384WITHECDSA" [c-sha384 "EC"]
    "SHA256WITHECDSA" [c-sha256 "EC"]
    "SHA224WITHECDSA" [c-sha224 "EC"]
    "SHA1WITHECDSA"   [c-sha1   "EC"]
    "SHA512WITHRSA"   [c-sha512 "RSA"]
    "SHA384WITHRSA"   [c-sha384 "RSA"]
    "SHA256WITHRSA"   [c-sha256 "RSA"]
    "SHA224WITHRSA"   [c-sha224 "RSA"]
    "SHA1WITHRSA"     [c-sha1   "RSA"]
    (throw (ex-info (str "unsupported Signature algorithm: " algo) {:algo algo}))))

(defn- digest-spec [algo]
  (case (str algo) ("SHA-512" "SHA512") [c-sha512 64] ("SHA-384" "SHA384") [c-sha384 48]
    ("SHA-256" "SHA256") [c-sha256 32] ("SHA-224" "SHA224") [c-sha224 28] ("SHA-1" "SHA1") [c-sha1 20]
    ("MD5") [c-md5 16]
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

;; --- X.509 shim objects -----------------------------------------------------
(defn- x509-cert? [x] (and (table? x) (= :jolt.crypto/x509-cert (tget x :jolt/type))))
(defn- x500-principal? [x] (and (table? x) (= :jolt.crypto/x500-principal (tget x :jolt/type))))
(defn- x500-name? [x] (and (table? x) (= :jolt.crypto/x500-name (tget x :jolt/type))))
(defn- ba= [a b] (and (bytes? a) (bytes? b) (= (seq a) (seq b))))

(defn- make-x509 [fields]
  (let [c (tt :jolt.crypto/x509-cert)]
    (doseq [[k v] fields] (tput! c k v))
    c))
(defn- x500-principal [rfc2253] (doto (tt :jolt.crypto/x500-principal) (tput! :name rfc2253)))

;; The head of the JVM's multi-line dump: version, subject, algorithm, key,
;; validity, issuer, serial.
(defn- x509-cert-string [c]
  (let [oid (tget c :sig-alg-oid)]
    (str "[\n[\n  Version: V" (tget c :version)
         "\n  Subject: " (rfc2253->rfc1779 (tget c :subject))
         "\n  Signature Algorithm: " (get sig-alg-names oid oid) ", OID = " oid
         "\n  Key:  " (:algorithm (tget c :public-key)) " public key"
         "\n  Validity: [From: " (java.util.Date. (tget c :not-before))
         ",\n               To: " (java.util.Date. (tget c :not-after)) "]"
         "\n  Issuer: " (rfc2253->rfc1779 (tget c :issuer))
         "\n  SerialNumber: [" (str/lower-case (.toString (tget c :serial) 16)) "]"
         "\n]\n]")))
(defn- x500-name [rfc2253] (doto (tt :jolt.crypto/x500-name) (tput! :name rfc2253)))

;; generateCertificate takes an InputStream on the JVM; bytes and a PEM string
;; are accepted too, since that is what a program has in hand.
(defn- cert-input-bytes [in]
  (cond (bytes? in) in
        (string? in) (.getBytes ^String in "UTF-8")
        :else (.readAllBytes in)))

(defn install! []
  ;; javax.crypto.spec.SecretKeySpec / IvParameterSpec — key + IV holders.
  (doseq [nm ["SecretKeySpec" "javax.crypto.spec.SecretKeySpec"]]
    (__register-class-ctor! nm (fn [key & _] (doto (tt :jolt.crypto/key) (tput! :bytes (byte-array key))))))
  (doseq [nm ["IvParameterSpec" "javax.crypto.spec.IvParameterSpec"]]
    (__register-class-ctor! nm (fn [iv & _] (doto (tt :jolt.crypto/iv) (tput! :bytes (byte-array iv))))))
  (__register-class-methods! :jolt.crypto/key {"getEncoded" (fn [self] (tget self :bytes))
                                               "getAlgorithm" (fn [self] (or (tget self :algo) "AES"))})

  ;; javax.crypto.Cipher — getInstance + ENCRYPT_MODE/DECRYPT_MODE, then the
  ;; stateful init/doFinal pair (Java's Cipher is mutable: init sets key+iv+mode).
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
     "doFinal" (fn [self data & _]
                 (aes-cbc (= ENCRYPT-MODE (tget self :mode)) (tget self :key) (tget self :iv) data))
     "getIV" (fn [self] (tget self :iv))
     "getBlockSize" (fn [self] 16)})

  ;; javax.crypto.Mac
  (doseq [nm ["Mac" "javax.crypto.Mac"]]
    (__register-class-statics! nm {"getInstance" (fn [algo & _] (doto (tt :jolt.crypto/mac) (tput! :md (mac-md algo))))}))
  (__register-class-methods! :jolt.crypto/mac
    {"init" (fn [self key & _] (tput! self :key (->ba key)) nil)
     "doFinal" (fn [self data & _] (let [[mdf len] (tget self :md)] (hmac mdf len (tget self :key) data)))
     "getMacLength" (fn [self] (let [[_ len] (tget self :md)] len))})

  ;; java.security.MessageDigest
  (doseq [nm ["MessageDigest" "java.security.MessageDigest"]]
    (__register-class-statics! nm {"getInstance" (fn [algo & _]
                                                   (let [[mdf len] (digest-spec algo)]
                                                     (doto (tt :jolt.crypto/md) (tput! :md mdf) (tput! :len len) (tput! :acc []))))}))
  (__register-class-methods! :jolt.crypto/md
    {"update" (fn [self data & _]
                (tput! self :acc (conj (tget self :acc) (snapshot-ba data)))
                nil)
     "digest" (fn [self & args]
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
                  (digest (tget self :md) (tget self :len) body)))
     "reset" (fn [self] (tput! self :acc []) nil)})

  ;; java.security.SecureRandom — real RAND_bytes (http-client's stub only made
  ;; a table; this fills the buffer for genuine randomness).
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

  ;; --- EC keys and ECDSA ----------------------------------------------------
  ;; java.security.spec: the three holders that carry a curve name or DER bytes.
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

  ;; java.security.KeyPairGenerator. Java's is stateful: getInstance picks the
  ;; algorithm, initialize picks the curve/size, generateKeyPair draws a key.
  (doseq [nm ["KeyPairGenerator" "java.security.KeyPairGenerator"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (case (str/upper-case (str algo))
                         "EC" (doto (tt :jolt.crypto/keypair-gen)
                                (tput! :algo "EC") (tput! :curve "secp256r1"))
                         ;; the JDK's default RSA size is 2048
                         "RSA" (doto (tt :jolt.crypto/keypair-gen)
                                 (tput! :algo "RSA") (tput! :bits 2048))
                         (throw (ex-info (str "unsupported KeyPairGenerator algorithm: " algo) {:algo algo}))))}))
  (__register-class-methods! :jolt.crypto/keypair-gen
    {;; initialize(AlgorithmParameterSpec) names the curve; initialize(int) gives
     ;; a key size in bits, which for EC selects the P-curve of that size and
     ;; for RSA is the modulus length. The curve is resolved here rather than at
     ;; generate time because that is where the JDK rejects an unknown one.
     "initialize" (fn [self spec & _]
                    (if (= "RSA" (tget self :algo))
                      (do
                        (when (table? spec)
                          (throw (ex-info (str "unsupported RSA parameter: " spec) {:spec spec})))
                        (let [bits (long spec)]
                          (when-not (<= 512 bits 16384)
                            (throw (ex-info (str "RSA key size must be between 512 and 16384 bits, got " bits)
                                            {:bits bits})))
                          (tput! self :bits bits)))
                      (let [curve (if (and (table? spec) (= :jolt.crypto/ec-params (tget spec :jolt/type)))
                                    (tget spec :curve)
                                    (case (long spec)
                                      256 "secp256r1" 384 "secp384r1" 521 "secp521r1"
                                      (throw (ex-info (str "unsupported EC key size: " spec) {:keysize spec}))))]
                        (curve-nid curve)
                        (tput! self :curve curve)))
                    nil)
     "generateKeyPair" (fn [self] (generate-keypair-for self))
     ;; genKeyPair is the older spelling of the same method
     "genKeyPair" (fn [self] (generate-keypair-for self))})
  (__register-class-methods! :jolt.crypto/keypair
    {"getPublic" (fn [self] (doto (tt :jolt.crypto/public-key)
                              (tput! :bytes (tget self :public))
                              (tput! :algo (tget self :algo))))
     "getPrivate" (fn [self] (doto (tt :jolt.crypto/private-key)
                               (tput! :bytes (tget self :private))
                               (tput! :algo (tget self :algo))))})

  ;; java.security.KeyFactory — DER key spec in, key object out. Decoding once
  ;; here means malformed bytes are rejected at generate* time, as on the JVM,
  ;; rather than surfacing later as a mysterious verification failure. d2i
  ;; accepts either algorithm's DER, so the parsed key's own NID — not the
  ;; algorithm the factory was asked for — is what the key gets stamped with,
  ;; and a disagreement between the two is an error, as it is on the JVM.
  (doseq [nm ["KeyFactory" "java.security.KeyFactory"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (case (str/upper-case (str algo))
                         "EC" (doto (tt :jolt.crypto/key-factory) (tput! :algo "EC"))
                         "RSA" (doto (tt :jolt.crypto/key-factory) (tput! :algo "RSA"))
                         (throw (ex-info (str "unsupported KeyFactory algorithm: " algo) {:algo algo}))))}))
  (__register-class-methods! :jolt.crypto/key-factory
    {"generatePublic" (fn [self spec]
                        (let [der (->ba spec)
                              algo (with-der-key c-d2i-pubkey der pkey-algo)]
                          (check-key-algo (tget self :algo) algo)
                          (doto (tt :jolt.crypto/public-key)
                            (tput! :bytes der) (tput! :algo (or algo (tget self :algo))))))
     "generatePrivate" (fn [self spec]
                         (let [der (->ba spec)
                               algo (with-der-key c-d2i-privkey der pkey-algo)]
                           (check-key-algo (tget self :algo) algo)
                           (doto (tt :jolt.crypto/private-key)
                             (tput! :bytes der) (tput! :algo (or algo (tget self :algo))))))
     "getAlgorithm" (fn [self] (tget self :algo))})

  ;; java.security.Signature — stateful like Cipher: init picks key and
  ;; direction, update accumulates, sign/verify consume and reset.
  (doseq [nm ["Signature" "java.security.Signature"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (let [[md key-algo] (signature-spec algo)]
                         (doto (tt :jolt.crypto/signature)
                           (tput! :md md)
                           (tput! :key-algo key-algo)
                           (tput! :algo (str algo))
                           (tput! :acc []))))}))
  (__register-class-methods! :jolt.crypto/signature
    {"initSign" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "initVerify" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "update" (fn [self data & _]
                (tput! self :acc (conj (tget self :acc) (snapshot-ba data)))
                nil)
     "sign" (fn [self & _]
              (let [body (concat-bas (tget self :acc))]
                (tput! self :acc [])
                (pkey-sign (tget self :md) (tget self :key) body (tget self :key-algo))))
     "verify" (fn [self sig & _]
                (let [body (concat-bas (tget self :acc))]
                  (tput! self :acc [])
                  (pkey-verify (tget self :md) (tget self :key) body sig (tget self :key-algo))))
     "getAlgorithm" (fn [self] (tget self :algo))})

  ;; --- X.509 certificates ---------------------------------------------------
  ;; java.security.cert.CertificateFactory / X509Certificate / X500Principal.
  ;; The exception family is registered into the class graph so a (catch
  ;; java.security.cert.CertificateException …) — or (catch Exception …) —
  ;; around generateCertificate catches what it throws.
  (doseq [[c supers] [["java.security.GeneralSecurityException" ["java.lang.Exception"]]
                      ["java.security.cert.CertificateException" ["java.security.GeneralSecurityException"]]
                      ["java.security.cert.CertificateEncodingException" ["java.security.cert.CertificateException"]]
                      ["java.security.cert.CertificateExpiredException" ["java.security.cert.CertificateException"]]
                      ["java.security.cert.CertificateNotYetValidException" ["java.security.cert.CertificateException"]]
                      ["java.security.cert.CertificateParsingException" ["java.security.cert.CertificateException"]]]]
    (jolt.host/register-class-supers! c supers))
  (doseq [nm ["CertificateFactory" "java.security.cert.CertificateFactory"]]
    (__register-class-statics! nm
      {"getInstance" (fn [type & _]
                       ;; getType answers the spelling asked for, as the JVM does
                       (when-not (#{"X.509" "X509"} (str type))
                         (throw (certificate-exception (str type " not found"))))
                       (doto (tt :jolt.crypto/cert-factory) (tput! :type (str type))))}))
  (__register-class-methods! :jolt.crypto/cert-factory
    {"getType" (fn [self] (tget self :type))
     "generateCertificate" (fn [self in] (make-x509 (first (parse-x509 (cert-input-bytes in)))))
     "generateCertificates" (fn [self in] (mapv make-x509 (parse-x509 (cert-input-bytes in))))})
  (__register-instance-check!
    (fn [cn val]
      (when (and (table? val) (= :jolt.crypto/x509-cert (tget val :jolt/type))
                 (#{"java.security.cert.X509Certificate" "X509Certificate"
                    "java.security.cert.Certificate" "Certificate"
                    "java.security.cert.X509Extension" "X509Extension"} cn))
        true)))
  (__register-class! x509-cert?
                     (fn [_] "java.security.cert.X509Certificate")
                     (fn [_] ["java.security.cert.X509Certificate" "java.security.cert.Certificate"
                              "java.security.cert.X509Extension" "java.io.Serializable"]))
  (__register-eq! (fn [a b] (or (x509-cert? a) (x509-cert? b)))
                  (fn [a b] (and (x509-cert? a) (x509-cert? b) (ba= (tget a :der) (tget b :der)))))
  (__register-hash! x509-cert? (fn [c] (hash (seq (tget c :der)))))
  (__register-str! x509-cert? (fn [c] (x509-cert-string c)))
  (__register-pr! x509-cert? (fn [c] (x509-cert-string c)))
  (__register-class-methods! :jolt.crypto/x509-cert
    {"getType" (fn [self] "X.509")
     "getEncoded" (fn [self] (aclone (tget self :der)))
     "getVersion" (fn [self] (tget self :version))
     "getSerialNumber" (fn [self] (tget self :serial))
     "getSubjectX500Principal" (fn [self] (x500-principal (tget self :subject)))
     "getIssuerX500Principal" (fn [self] (x500-principal (tget self :issuer)))
     "getSubjectDN" (fn [self] (x500-name (tget self :subject)))
     "getIssuerDN" (fn [self] (x500-name (tget self :issuer)))
     "getNotBefore" (fn [self] (java.util.Date. (tget self :not-before)))
     "getNotAfter" (fn [self] (java.util.Date. (tget self :not-after)))
     "getSigAlgOID" (fn [self] (tget self :sig-alg-oid))
     "getSigAlgName" (fn [self] (let [oid (tget self :sig-alg-oid)] (get sig-alg-names oid oid)))
     ;; the same PublicKey KeyFactory builds, so it initVerify's a Signature
     "getPublicKey" (fn [self]
                      (let [{:keys [algorithm der]} (tget self :public-key)]
                        (doto (tt :jolt.crypto/public-key) (tput! :bytes der) (tput! :algo algorithm))))
     ;; checkValidity() is now; checkValidity(Date) is that instant
     "checkValidity" (fn [self & [date]]
                       (let [now (if date (.getTime date) (System/currentTimeMillis))
                             not-before (tget self :not-before) not-after (tget self :not-after)]
                         (cond
                           (< now not-before)
                           (throw (jolt.host/throwable "java.security.cert.CertificateNotYetValidException"
                                                       (str "NotBefore: " (java.util.Date. not-before))))
                           (> now not-after)
                           (throw (jolt.host/throwable "java.security.cert.CertificateExpiredException"
                                                       (str "NotAfter: " (java.util.Date. not-after)))))
                         nil))
     "hashCode" (fn [self] (hash (seq (tget self :der))))
     "equals" (fn [self o] (and (x509-cert? o) (ba= (tget self :der) (tget o :der))))
     "toString" (fn [self] (x509-cert-string self))})
  ;; javax.security.auth.x500.X500Principal (getName is RFC 2253) and the
  ;; java.security.Principal getSubjectDN/getIssuerDN answer (getName is the
  ;; RFC 1779 spelling X500Name.toString uses).
  (doseq [nm ["X500Principal" "javax.security.auth.x500.X500Principal"]]
    (__register-class-ctor! nm (fn [name & _] (x500-principal (str name)))))
  (__register-instance-check!
    (fn [cn val]
      (when (and (table? val) (#{:jolt.crypto/x500-principal :jolt.crypto/x500-name} (tget val :jolt/type))
                 (or (#{"java.security.Principal" "Principal"} cn)
                     (and (= :jolt.crypto/x500-principal (tget val :jolt/type))
                          (#{"javax.security.auth.x500.X500Principal" "X500Principal"} cn))))
        true)))
  (__register-class! x500-principal?
                     (fn [_] "javax.security.auth.x500.X500Principal")
                     (fn [_] ["javax.security.auth.x500.X500Principal" "java.security.Principal" "java.io.Serializable"]))
  (__register-eq! (fn [a b] (or (x500-principal? a) (x500-principal? b)))
                  (fn [a b] (and (x500-principal? a) (x500-principal? b) (= (tget a :name) (tget b :name)))))
  (__register-hash! x500-principal? (fn [p] (hash (tget p :name))))
  (__register-str! x500-principal? (fn [p] (rfc2253->rfc1779 (tget p :name))))
  (__register-pr! x500-principal? (fn [p] (rfc2253->rfc1779 (tget p :name))))
  (__register-str! x500-name? (fn [p] (rfc2253->rfc1779 (tget p :name))))
  (__register-pr! x500-name? (fn [p] (rfc2253->rfc1779 (tget p :name))))
  (__register-class-methods! :jolt.crypto/x500-principal
    {"getName" (fn [self & [format]]
                 (case (some-> format str str/upper-case)
                   (nil "RFC2253") (tget self :name)
                   "RFC1779" (rfc2253->rfc1779 (tget self :name))
                   "CANONICAL" (str/lower-case (tget self :name))
                   (throw (ex-info (str "invalid format specified: " format) {:format format}))))
     "toString" (fn [self] (rfc2253->rfc1779 (tget self :name)))
     "hashCode" (fn [self] (hash (tget self :name)))
     "equals" (fn [self o] (and (x500-principal? o) (= (tget self :name) (tget o :name))))})
  (__register-class-methods! :jolt.crypto/x500-name
    {"getName" (fn [self] (rfc2253->rfc1779 (tget self :name)))
     "toString" (fn [self] (rfc2253->rfc1779 (tget self :name)))})
  nil)

(install!)
