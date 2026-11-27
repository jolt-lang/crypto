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
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.internal.openssl :as openssl]
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

;; EVP keys and ECDSA/RSASSA-PKCS1-v1_5. EVP_EC_gen is a macro rather
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
(ffi/defcfn c-pem-read-privkey "PEM_read_bio_PrivateKey" [:pointer :pointer :pointer :pointer] :pointer)
(ffi/defcfn c-pem-read-pubkey  "PEM_read_bio_PUBKEY"     [:pointer :pointer :pointer :pointer] :pointer)
(ffi/defcfn c-des-set-key-unchecked "DES_set_key_unchecked" [:pointer :pointer] :void)
(ffi/defcfn c-des-cbc-encrypt "DES_cbc_encrypt" [:pointer :pointer :long :pointer :pointer :int] :void)
(ffi/defcfn c-md-ctx-new   "EVP_MD_CTX_new"           [] :pointer)
(ffi/defcfn c-md-ctx-free  "EVP_MD_CTX_free"          [:pointer] :void)
(ffi/defcfn c-dgst-sign-init   "EVP_DigestSignInit"   [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dgst-sign        "EVP_DigestSign"       [:pointer :pointer :pointer :pointer :size_t] :int)
(ffi/defcfn c-dgst-verify-init "EVP_DigestVerifyInit" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dgst-verify      "EVP_DigestVerify"     [:pointer :pointer :size_t :pointer :size_t] :int)
(ffi/defcfn c-rsa-padding      "EVP_PKEY_CTX_set_rsa_padding" [:pointer :int] :int)
(ffi/defcfn c-rsa-pss-saltlen  "EVP_PKEY_CTX_set_rsa_pss_saltlen" [:pointer :int] :int)
(ffi/defcfn c-rsa-mgf1-md      "EVP_PKEY_CTX_set_rsa_mgf1_md" [:pointer :pointer] :int)

;; RSA keygen. RSA_generate_key_ex takes the public exponent as a BIGNUM, so a
;; BN_new/BN_set_word pair sets the usual 65537 (F4) before the call.
(ffi/defcfn c-rsa-new      "RSA_new"             [] :pointer)
(ffi/defcfn c-rsa-gen      "RSA_generate_key_ex" [:pointer :int :pointer :pointer] :int)
(ffi/defcfn c-rsa-free     "RSA_free"            [:pointer] :void)
(ffi/defcfn c-bn-new       "BN_new"              [] :pointer)
(ffi/defcfn c-bn-set-word  "BN_set_word"         [:pointer :ulong] :int)
(ffi/defcfn c-bn-free      "BN_free"             [:pointer] :void)
(ffi/defcfn c-pkey-set-rsa "EVP_PKEY_set1_RSA"   [:pointer :pointer] :int)

;; JWK parameter construction and inspection. BIGNUMs are copied into OpenSSL
;; keys, and every native key/point is released before the public byte/map value
;; is returned. RSA_set0_* transfers ownership only on success.
(ffi/defcfn c-bn-bin2bn       "BN_bin2bn"           [:pointer :int :pointer] :pointer)
(ffi/defcfn c-bn-bn2bin       "BN_bn2bin"           [:pointer :pointer] :int)
(ffi/defcfn c-bn-num-bits     "BN_num_bits"         [:pointer] :int)
(ffi/defcfn c-rsa-set0-key    "RSA_set0_key"        [:pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-rsa-set0-factors "RSA_set0_factors"   [:pointer :pointer :pointer] :int)
(ffi/defcfn c-rsa-set0-crt    "RSA_set0_crt_params" [:pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-rsa-get0-key    "RSA_get0_key"        [:pointer :pointer :pointer :pointer] :void)
(ffi/defcfn c-rsa-get0-factors "RSA_get0_factors"   [:pointer :pointer :pointer] :void)
(ffi/defcfn c-rsa-get0-crt    "RSA_get0_crt_params" [:pointer :pointer :pointer :pointer] :void)
(ffi/defcfn c-rsa-check       "RSA_check_key"       [:pointer] :int)
(ffi/defcfn c-pkey-get-rsa    "EVP_PKEY_get1_RSA"   [:pointer] :pointer)
(ffi/defcfn c-ec-set-private  "EC_KEY_set_private_key" [:pointer :pointer] :int)
(ffi/defcfn c-ec-set-public   "EC_KEY_set_public_key"  [:pointer :pointer] :int)
(ffi/defcfn c-ec-get0-group   "EC_KEY_get0_group"      [:pointer] :pointer)
(ffi/defcfn c-ec-get0-private "EC_KEY_get0_private_key" [:pointer] :pointer)
(ffi/defcfn c-ec-get0-public  "EC_KEY_get0_public_key"  [:pointer] :pointer)
(ffi/defcfn c-ec-check        "EC_KEY_check_key"       [:pointer] :int)
(ffi/defcfn c-ec-group-nid    "EC_GROUP_get_curve_name" [:pointer] :int)
(ffi/defcfn c-ec-point-new    "EC_POINT_new"          [:pointer] :pointer)
(ffi/defcfn c-ec-point-free   "EC_POINT_free"         [:pointer] :void)
(ffi/defcfn c-ec-point-set    "EC_POINT_set_affine_coordinates" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-ec-point-mul    "EC_POINT_mul"          [:pointer :pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-ec-point-octets "EC_POINT_point2oct"    [:pointer :pointer :int :pointer :size_t :pointer] :size_t)
(ffi/defcfn c-pkey-get-ec     "EVP_PKEY_get1_EC_KEY"  [:pointer] :pointer)

;; Ed25519 keygen goes through an EVP_PKEY_CTX for the key type (NID 1087).
;; These are exported functions in both 1.1.1 and 3. Signing needs nothing
;; new: EVP_DigestSign/EVP_DigestVerify with a NULL digest are Ed25519's
;; one-shot (PureEdDSA) path.
(ffi/defcfn c-pkey-ctx-new-id  "EVP_PKEY_CTX_new_id"  [:int :pointer] :pointer)
(ffi/defcfn c-pkey-keygen-init "EVP_PKEY_keygen_init" [:pointer] :int)
(ffi/defcfn c-pkey-keygen      "EVP_PKEY_keygen"      [:pointer :pointer] :int)
(ffi/defcfn c-pkey-ctx-free    "EVP_PKEY_CTX_free"    [:pointer] :void)
(ffi/defcfn c-pkey-new-raw-private "EVP_PKEY_new_raw_private_key" [:int :pointer :pointer :size_t] :pointer)
(ffi/defcfn c-pkey-new-raw-public  "EVP_PKEY_new_raw_public_key"  [:int :pointer :pointer :size_t] :pointer)
(ffi/defcfn c-pkey-get-raw-private "EVP_PKEY_get_raw_private_key" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-pkey-get-raw-public  "EVP_PKEY_get_raw_public_key"  [:pointer :pointer :pointer] :int)

;; OpenSSL 3 reports the decoded key's concrete type directly. This avoids
;; guessing from filenames or probing algorithm-specific getters.
(ffi/defcfn c-pkey-type-name "EVP_PKEY_get0_type_name" [:pointer] :pointer)
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

(defn- ba-window
  "A copy of the [off, off+len) window of a byte array — the JVM's
  update/digest/doFinal (bytes, off, len) overloads consume exactly this."
  [x off len]
  (let [src (as-ba x) out (byte-array len)]
    (System/arraycopy src off out 0 len)
    out))

(defn- consume-update-args
  "Snapshot one update() payload: (data) is the whole array, (data off len) the
  window. Either way the caller's bytes are consumed now, not retained."
  [data more]
  (if (= 2 (count more))
    (ba-window data (first more) (second more))
    (snapshot-ba data)))

(defn- concat-bas
  "Join byte arrays with bulk copies."
  [bas]
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

(defn- pkey-type [pkey]
  (let [name-ptr (c-pkey-type-name pkey)]
    (when-not (ffi/null? name-ptr)
      (case (ffi/ptr->string name-ptr)
        "ED25519" "Ed25519"
        "ED448" "Ed448"
        (ffi/ptr->string name-ptr)))))

(defn- pkey-algo
  "The JDK algorithm name for a parsed OpenSSL key."
  [pkey]
  (case (pkey-type pkey)
    "Ed25519" "EdDSA"
    "Ed448" "EdDSA"
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
    (with-der-key c-d2i-pubkey der #(decoded-key :jolt.crypto/public-key der %))))

(defn decode-private-key
  "Decode a PKCS#8 PrivateKeyInfo DER value into a tagged PrivateKey."
  [der]
  (let [der (as-ba der)]
    (with-der-key c-d2i-privkey der #(decoded-key :jolt.crypto/private-key der %))))

(declare with-mem-bio parse-x509)

;; OpenSSL 3's generic PKCS#8 decoder rejects the pbeWithMD5AndDES-CBC fixture
;; even though DES-CBC remains available through exported low-level functions.
;; Support that exact PBE here, without loading the legacy provider; all other
;; encrypted PKCS#8 inputs continue through the generic decoder first.
(defn- encrypted-pem? [text]
  (or (str/includes? text "Proc-Type: 4,ENCRYPTED")
      (str/includes? text "-----BEGIN ENCRYPTED PRIVATE KEY-----")))

(defn- malformed-pkcs8 []
  (throw (ex-info "Malformed or unsupported encrypted PKCS#8 key" {})))

(defn- der-node [der offset]
  (let [size (alength der)]
    (when (> (+ offset 2) size) (malformed-pkcs8))
    (let [tag (bit-and (aget der offset) 0xff)
          first-length (bit-and (aget der (inc offset)) 0xff)
          length-bytes (if (zero? (bit-and first-length 0x80))
                         0
                         (bit-and first-length 0x7f))
          content-offset (+ offset 2 length-bytes)]
      ;; 0x80 is BER's indefinite length, which DER forbids.
      (when (or (= first-length 0x80) (> length-bytes 4) (> content-offset size))
        (malformed-pkcs8))
      (let [content-length (if (zero? length-bytes)
                             first-length
                             (loop [index 0 length 0]
                               (if (= index length-bytes)
                                 length
                                 (recur (inc index)
                                        (+ (* 256 length)
                                           (bit-and (aget der (+ offset 2 index)) 0xff))))))
            end (+ content-offset content-length)]
        ;; DER lengths are minimal: long form only from 128, no leading zero byte.
        (when (and (pos? length-bytes)
                   (or (< content-length 128)
                       (zero? (bit-and (aget der (+ offset 2)) 0xff))))
          (malformed-pkcs8))
        (when (> end size) (malformed-pkcs8))
        {:tag tag :start content-offset :end end :next end}))))

(defn- der-child [der parent offset tag]
  (let [node (der-node der offset)]
    (when (or (not= tag (:tag node)) (> (:next node) (:end parent)))
      (malformed-pkcs8))
    node))

(def ^:private max-pbkdf1-iterations 10000000)

(def ^:private pbe-md5-des-oid
  [0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x05 0x03])

(defn- der-content= [der node expected]
  (and (= (count expected) (- (:end node) (:start node)))
       (= expected (mapv #(bit-and % 0xff)
                         (ba-window der (:start node) (count expected))))))

(defn- der-positive-int [der node]
  (let [length (- (:end node) (:start node))]
    (when-not (<= 1 length 4) (malformed-pkcs8))
    (when (pos? (bit-and (aget der (:start node)) 0x80)) (malformed-pkcs8))
    (let [value (loop [offset (:start node) value 0]
                  (if (= offset (:end node))
                    value
                    (recur (inc offset)
                           (+ (* 256 value) (bit-and (aget der offset) 0xff)))))]
      (when-not (pos? value) (malformed-pkcs8))
      value)))

(defn- encrypted-pkcs8-fields [text]
  (let [body (or (second (re-find #"(?s)-----BEGIN ENCRYPTED PRIVATE KEY-----\s*(.*?)-----END ENCRYPTED PRIVATE KEY-----" text))
                 (malformed-pkcs8))
        der (try
              (codecs/b64->bytes (.getBytes (str/replace body #"\s" "") "UTF-8"))
              (catch Exception _ (malformed-pkcs8)))
        outer (der-node der 0)
        _ (when (or (not= 0x30 (:tag outer)) (not= (alength der) (:next outer)))
            (malformed-pkcs8))
        algorithm (der-child der outer (:start outer) 0x30)
        oid (der-child der algorithm (:start algorithm) 0x06)
        _ (when-not (der-content= der oid pbe-md5-des-oid)
            (throw (ex-info "Not a pbeWithMD5AndDES key" {::not-md5-des true})))
        params (der-child der algorithm (:next oid) 0x30)
        salt (der-child der params (:start params) 0x04)
        _ (when-not (= 8 (- (:end salt) (:start salt))) (malformed-pkcs8))
        iterations-node (der-child der params (:next salt) 0x02)
        _ (when-not (= (:next iterations-node) (:end params)) (malformed-pkcs8))
        iterations (der-positive-int der iterations-node)
        ;; One MD5 call per iteration: a hostile file must not hang the caller.
        _ (when (> iterations max-pbkdf1-iterations) (malformed-pkcs8))
        _ (when-not (= (:next params) (:end algorithm)) (malformed-pkcs8))
        ciphertext (der-child der outer (:next algorithm) 0x04)
        ciphertext-length (- (:end ciphertext) (:start ciphertext))
        _ (when (or (zero? ciphertext-length) (not (zero? (mod ciphertext-length 8)))
                    (not= (:next ciphertext) (:end outer)))
            (malformed-pkcs8))]
    {:salt (ba-window der (:start salt) 8)
     :iterations iterations
     :ciphertext (ba-window der (:start ciphertext) ciphertext-length)}))

(defn- pbkdf1-md5 [password salt iterations]
  (loop [iteration 1
         value (digest c-md5 16 (concat-bas [password salt]))]
    (if (= iteration iterations)
      value
      (recur (inc iteration) (digest c-md5 16 value)))))

(defn- des-cbc-decrypt [key iv ciphertext]
  (when-not (zero? (mod (alength ciphertext) 8))
    (throw (ex-info "DES-CBC input must contain complete blocks" {})))
  (with-ptrs [ciphertext key iv]
    (fn [input-ptr key-ptr iv-ptr]
      (let [schedule (ffi/alloc 128)
            output (ffi/alloc (max 1 (alength ciphertext)))]
        (try
          (c-des-set-key-unchecked key-ptr schedule)
          (c-des-cbc-encrypt input-ptr output (alength ciphertext) schedule iv-ptr 0)
          (ffi/read-array output (alength ciphertext))
          (finally
            (ffi/free schedule)
            (ffi/free output)))))))

(defn- remove-pkcs7-padding [padded]
  (let [length (alength padded)]
    (when (zero? length) (throw (ex-info "Invalid DES-CBC padding" {})))
    (let [padding (bit-and (aget padded (dec length)) 0xff)]
      (when (or (zero? padding) (> padding 8) (> padding length))
        (throw (ex-info "Invalid DES-CBC padding" {})))
      (dotimes [index padding]
        (when-not (= padding (bit-and (aget padded (- length 1 index)) 0xff))
          (throw (ex-info "Invalid DES-CBC padding" {}))))
      (ba-window padded 0 (- length padding)))))

(defn- decode-pkcs8-md5-des [text passphrase]
  (let [{:keys [salt iterations ciphertext]} (encrypted-pkcs8-fields text)
        password (.getBytes passphrase "UTF-8")
        derived (pbkdf1-md5 password salt iterations)
        key (ba-window derived 0 8)
        iv (ba-window derived 8 8)
        plaintext (remove-pkcs7-padding (des-cbc-decrypt key iv ciphertext))]
    (decode-private-key plaintext)))

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
                         (c-err-clear)
                         (let [pkey (c-pem-read-privkey bio ffi/null ffi/null password)]
                           (when (ffi/null? pkey)
                             (c-err-clear)
                             (throw (ex-info "Could not decode PEM private key" {})))
                           (try
                             (let [p8 (c-pkey->p8 pkey)]
                               (when (ffi/null? p8)
                                 (throw (ex-info "PKCS#8 conversion failed" {})))
                               (try
                                 (decode-private-key (der-out c-i2d-p8 p8))
                                 (finally (c-p8-free p8))))
                             (finally (c-pkey-free pkey)))))]
            (if (nil? passphrase)
              (decode ffi/null)
              (ffi/with-c-string [password passphrase]
                (decode password))))))
      (catch clojure.lang.ExceptionInfo e
        (if (str/includes? text "-----BEGIN ENCRYPTED PRIVATE KEY-----")
          ;; Only legacy pbeWithMD5AndDES keys fall back; any other scheme keeps
          ;; OpenSSL's own failure (a wrong passphrase, say).
          (try
            (decode-pkcs8-md5-des text passphrase)
            (catch clojure.lang.ExceptionInfo fallback
              (throw (if (::not-md5-des (ex-data fallback)) e fallback))))
          (throw e))))))

(defn decode-pem-public-key
  "Decode a PEM SubjectPublicKeyInfo or X.509 certificate public key."
  [bytes]
  (let [bytes (as-ba bytes)
        text (String. bytes "UTF-8")]
    (if (str/includes? text "-----BEGIN CERTIFICATE-----")
      (decode-public-key (:der (:public-key (first (parse-x509 bytes)))))
      (with-mem-bio bytes
        (fn [bio]
          (c-err-clear)
          (let [pkey (c-pem-read-pubkey bio ffi/null ffi/null ffi/null)]
            (when (ffi/null? pkey)
              (c-err-clear)
              (throw (ex-info "Could not decode PEM public key or certificate" {})))
            (try
              (decode-public-key (der-out c-i2d-pubkey pkey))
              (finally (c-pkey-free pkey)))))))))

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

(def ^:private nid-ed25519 1087)
(def ^:private nid-ed448 1088)

(defn generate-ed25519-keypair
  "Generate an Ed25519 keypair. Returns {:public <X.509 DER> :private <PKCS#8 DER>},
  the same two encodings the JVM's getEncoded hands back."
  []
  (let [ctx (c-pkey-ctx-new-id nid-ed25519 ffi/null)]
    (when (ffi/null? ctx) (throw (ex-info "Ed25519 key setup failed" {})))
    (try
      (when (not= 1 (c-pkey-keygen-init ctx)) (throw (ex-info "Ed25519 keygen init failed" {})))
      (let [holder (ffi/alloc ptr-size)]
        (try
          (ffi/write holder :pointer ffi/null 0)
          (when (not= 1 (c-pkey-keygen ctx holder)) (throw (ex-info "Ed25519 key generation failed" {})))
          (let [pkey (ffi/read holder :pointer)]
            (try
              (let [p8 (c-pkey->p8 pkey)]
                (when (ffi/null? p8) (throw (ex-info "PKCS#8 conversion failed" {})))
                (try {:public (der-out c-i2d-pubkey pkey) :private (der-out c-i2d-p8 p8)}
                     (finally (c-p8-free p8))))
              (finally (c-pkey-free pkey))))
          (finally (ffi/free holder))))
      (finally (c-pkey-ctx-free ctx)))))

;; --- JWK key parameter boundary ---------------------------------------------
;; These functions are public only so the jwk namespaces can share the existing
;; OpenSSL shim. Their values contain bytes, strings, and tagged DER keys only.
(defn- bn-from-unsigned [data]
  (let [data (as-ba data)]
    (with-ptrs [data]
      (fn [ptr]
        (let [bn (c-bn-bin2bn ptr (alength data) ffi/null)]
          (when (ffi/null? bn)
            (throw (ex-info "OpenSSL BIGNUM initialization failed" {})))
          bn)))))

(defn- bn->unsigned [bn]
  (when-not (ffi/null? bn)
    (let [length (quot (+ (c-bn-num-bits bn) 7) 8)
          output (ffi/alloc (max 1 length))]
      (try
        (let [written (c-bn-bn2bin bn output)]
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
        (doseq [bn @owned] (c-bn-free bn))
        (c-err-clear)
        (throw e)))))

(defn- check-native-key [check-fn key algorithm]
  (when-not (= 1 (check-fn key))
    (c-err-clear)
    (throw (ex-info (str "Invalid " algorithm " key parameters") {}))))

(defn rsa-public-from-parameters
  "Build a tagged RSA PublicKey from unsigned n and e bytes. JWK-internal."
  [n e]
  (let [rsa (c-rsa-new)]
    (when (ffi/null? rsa)
      (throw (ex-info "OpenSSL RSA allocation failed" {})))
    (try
      (rsa-set0! rsa c-rsa-set0-key [n e nil])
      (let [pkey (c-pkey-new)]
        (when (ffi/null? pkey)
          (throw (ex-info "OpenSSL EVP_PKEY allocation failed" {})))
        (try
          (when-not (= 1 (c-pkey-set-rsa pkey rsa))
            (throw (ex-info "OpenSSL RSA key wrapping failed" {})))
          (decode-public-key (der-out c-i2d-pubkey pkey))
          (finally (c-pkey-free pkey))))
      (finally (c-rsa-free rsa)))))

(defn rsa-private-from-parameters
  "Build a tagged RSA PrivateKey from a complete unsigned parameter map."
  [{:keys [n e d p q dp dq qi]}]
  (let [rsa (c-rsa-new)]
    (when (ffi/null? rsa)
      (throw (ex-info "OpenSSL RSA allocation failed" {})))
    (try
      (rsa-set0! rsa c-rsa-set0-key [n e d])
      (rsa-set0! rsa c-rsa-set0-factors [p q])
      (rsa-set0! rsa c-rsa-set0-crt [dp dq qi])
      (check-native-key c-rsa-check rsa "RSA")
      (let [pkey (c-pkey-new)]
        (when (ffi/null? pkey)
          (throw (ex-info "OpenSSL EVP_PKEY allocation failed" {})))
        (try
          (when-not (= 1 (c-pkey-set-rsa pkey rsa))
            (throw (ex-info "OpenSSL RSA key wrapping failed" {})))
          (let [p8 (c-pkey->p8 pkey)]
            (when (ffi/null? p8)
              (c-err-clear)
              (throw (ex-info "OpenSSL RSA PKCS#8 encoding failed" {})))
            (try
              (decode-private-key (der-out c-i2d-p8 p8))
              (finally (c-p8-free p8))))
          (finally (c-pkey-free pkey))))
      (finally (c-rsa-free rsa)))))

(defn- with-rsa-parameters [key private? f]
  (with-der-key (if private? c-d2i-privkey c-d2i-pubkey) (tget key :bytes)
    (fn [pkey]
      (let [rsa (c-pkey-get-rsa pkey)]
        (when (ffi/null? rsa)
          (c-err-clear)
          (throw (ex-info "Expected an RSA key" {})))
        (try
          (let [holders (ffi/alloc (* 8 ptr-size))]
            (try
              (c-rsa-get0-key rsa holders (+ holders ptr-size) (+ holders (* 2 ptr-size)))
              (c-rsa-get0-factors rsa (+ holders (* 3 ptr-size)) (+ holders (* 4 ptr-size)))
              (c-rsa-get0-crt rsa (+ holders (* 5 ptr-size)) (+ holders (* 6 ptr-size))
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
          (finally (c-rsa-free rsa)))))))

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
  (let [group (c-ec-get0-group eck)
        point (c-ec-point-new group)]
    (when (ffi/null? point)
      (throw (ex-info "OpenSSL EC point allocation failed" {})))
    (let [xbn (atom nil)
          ybn (atom nil)]
      (try
        (reset! xbn (bn-from-unsigned x))
        (reset! ybn (bn-from-unsigned y))
        (when-not (= 1 (c-ec-point-set group point @xbn @ybn ffi/null))
          (c-err-clear)
          (throw (ex-info "OpenSSL EC coordinate initialization failed" {})))
        (when-not (= 1 (c-ec-set-public eck point))
          (c-err-clear)
          (throw (ex-info "OpenSSL EC public key initialization failed" {})))
        (finally
          (c-ec-point-free point)
          (when @xbn (c-bn-free @xbn))
          (when @ybn (c-bn-free @ybn)))))))

(defn- ec-pkey->der [eck private?]
  (let [pkey (c-pkey-new)]
    (when (ffi/null? pkey)
      (throw (ex-info "OpenSSL EVP_PKEY allocation failed" {})))
    (try
      (when-not (= 1 (c-pkey-set-ec pkey eck))
        (throw (ex-info "OpenSSL EC key wrapping failed" {})))
      (if private?
        (let [p8 (c-pkey->p8 pkey)]
          (when (ffi/null? p8)
            (c-err-clear)
            (throw (ex-info "OpenSSL EC PKCS#8 encoding failed" {})))
          (try
            (decode-private-key (der-out c-i2d-p8 p8))
            (finally (c-p8-free p8))))
        (decode-public-key (der-out c-i2d-pubkey pkey)))
      (finally (c-pkey-free pkey)))))

(defn ec-public-from-parameters
  "Build a tagged EC PublicKey from a JWK curve and unsigned x/y bytes."
  [curve x y]
  (let [eck (c-ec-new-curve (curve-nid curve))]
    (when (ffi/null? eck)
      (throw (ex-info (str "Unsupported EC curve: " curve) {:curve curve})))
    (try
      (ec-set-public! eck x y)
      (check-native-key c-ec-check eck "EC")
      (ec-pkey->der eck false)
      (finally (c-ec-free eck)))))

(defn ec-private-from-parameters
  "Build a tagged EC PrivateKey from a JWK curve and unsigned d/x/y bytes."
  [curve d x y]
  (let [eck (c-ec-new-curve (curve-nid curve))]
    (when (ffi/null? eck)
      (throw (ex-info (str "Unsupported EC curve: " curve) {:curve curve})))
    (try
      (ec-set-public! eck x y)
      (let [dbn (bn-from-unsigned d)]
        (try
          (when-not (= 1 (c-ec-set-private eck dbn))
            (c-err-clear)
            (throw (ex-info "OpenSSL EC private key initialization failed" {})))
          (finally (c-bn-free dbn))))
      (check-native-key c-ec-check eck "EC")
      (ec-pkey->der eck true)
      (finally (c-ec-free eck)))))

(def ^:private jwk-curves
  {415 ["P-256" 32] 714 ["secp256k1" 32]
   715 ["P-384" 48] 716 ["P-521" 66]})

(defn- ec-point-fields [eck derive?]
  (let [group (c-ec-get0-group eck)
        nid (c-ec-group-nid group)
        [curve width] (or (get jwk-curves nid)
                          (throw (ex-info "Unsupported EC curve" {:nid nid})))
        existing (c-ec-get0-public eck)
        derive (and (ffi/null? existing) derive?)
        point (if derive (c-ec-point-new group) existing)]
    (when (ffi/null? point)
      (throw (ex-info "EC key has no public point" {})))
    (try
      (when derive
        (when-not (= 1 (c-ec-point-mul group point ffi/null ffi/null
                                       (c-ec-get0-private eck) ffi/null))
          (c-err-clear)
          (throw (ex-info "OpenSSL EC public key derivation failed" {}))))
      (let [expected (inc (* 2 width))
            actual (c-ec-point-octets group point 4 ffi/null 0 ffi/null)]
        (when-not (= expected actual)
          (throw (ex-info "Unexpected EC point width" {:expected expected :actual actual})))
        (let [buffer (ffi/alloc actual)]
          (try
            (when-not (= actual (c-ec-point-octets group point 4 buffer actual ffi/null))
              (throw (ex-info "OpenSSL EC point encoding failed" {})))
            (let [encoded (ffi/read-array buffer actual)]
              {:crv curve
               :x (ba-window encoded 1 width)
               :y (ba-window encoded (inc width) width)})
            (finally (ffi/free buffer)))))
      (finally
        (when derive (c-ec-point-free point))))))

(defn- with-ec-parameters [key private? f]
  (with-der-key (if private? c-d2i-privkey c-d2i-pubkey) (tget key :bytes)
    (fn [pkey]
      (let [eck (c-pkey-get-ec pkey)]
        (when (ffi/null? eck)
          (c-err-clear)
          (throw (ex-info "Expected an EC key" {})))
        (try (f eck) (finally (c-ec-free eck)))))))

(defn ec-public-parameters
  "Return {:crv string :x bytes :y bytes} from a tagged EC PublicKey."
  [key]
  (with-ec-parameters key false #(ec-point-fields % false)))

(defn ec-private-parameters
  "Return curve/public coordinates and unsigned d bytes from an EC PrivateKey."
  [key]
  (with-ec-parameters key true
    (fn [eck]
      (let [private (c-ec-get0-private eck)]
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
        (let [pkey ((if private? c-pkey-new-raw-private c-pkey-new-raw-public)
                    nid ffi/null ptr length)]
          (when (ffi/null? pkey)
            (c-err-clear)
            (throw (ex-info (str "OpenSSL " curve " raw key initialization failed") {})))
          (try
            (if private?
              (let [p8 (c-pkey->p8 pkey)]
                (when (ffi/null? p8)
                  (throw (ex-info (str curve " PKCS#8 encoding failed") {})))
                (try
                  (decode-private-key (der-out c-i2d-p8 p8))
                  (finally (c-p8-free p8))))
              (decode-public-key (der-out c-i2d-pubkey pkey)))
            (finally (c-pkey-free pkey))))))))

(defn ed-private-from-raw
  "Build a tagged Ed25519/Ed448 PrivateKey from its raw private bytes."
  [curve raw]
  (ed-from-raw curve raw true))

(defn ed-public-from-raw
  "Build a tagged Ed25519/Ed448 PublicKey from its raw public bytes."
  [curve raw]
  (ed-from-raw curve raw false))

(defn- ed-raw-from-key [key private? raw-kind]
  (with-der-key (if private? c-d2i-privkey c-d2i-pubkey) (tget key :bytes)
    (fn [pkey]
      (let [length-holder (ffi/alloc 8)]
        (try
          (let [getter (if (= :private raw-kind) c-pkey-get-raw-private c-pkey-get-raw-public)]
            (when-not (= 1 (getter pkey ffi/null length-holder))
              (c-err-clear)
              (throw (ex-info "OpenSSL raw EdDSA key sizing failed" {})))
            (let [length (ffi/read length-holder :size_t)
                  buffer (ffi/alloc length)]
              (try
                (when-not (= 1 (getter pkey buffer length-holder))
                  (c-err-clear)
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
                                   (generate-ec-keypair (tget self :curve)))]
    (doto (tt :jolt.crypto/keypair)
      (tput! :public public)
      (tput! :private private)
      (tput! :algo (tget self :algo))
      (tput! :key-type (if (= "EdDSA" (tget self :algo)) "Ed25519" (tget self :algo))))))

(def ^:private rsa-pkcs1-pss-padding 6)
(def ^:private rsa-pss-saltlen-digest -1)

(defn- configure-pss! [pctx md-fn]
  (when (ffi/null? pctx)
    (throw (ex-info "RSA-PSS context initialization failed" {})))
  (when (not= 1 (c-rsa-padding pctx rsa-pkcs1-pss-padding))
    (throw (ex-info "RSA-PSS padding setup failed" {})))
  (when (not= 1 (c-rsa-mgf1-md pctx (md-fn)))
    (throw (ex-info "RSA-PSS MGF1 setup failed" {})))
  (when (not= 1 (c-rsa-pss-saltlen pctx rsa-pss-saltlen-digest))
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
   (with-der-key c-d2i-privkey priv-der
     (fn [pkey]
       (check-signature-options pkey want-algo options)
       (let [data (as-ba data) dn (alength data) ctx (c-md-ctx-new)]
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
                       (when (not= 1 (c-dgst-sign-init ctx pctxp (if md-fn (md-fn) ffi/null) ffi/null pkey))
                         (throw (ex-info "signature init failed" {})))
                       (when (:pss options)
                         (configure-pss! (ffi/read pctxp :pointer) md-fn))
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
                       (finally
                         ;; DigestSignInit transferred pctx ownership to ctx.
                         (ffi/free pctxp))))
                   (finally (ffi/free lenp))))))
           (finally (c-md-ctx-free ctx))))))))

(defn pkey-verify
  "Verify a signature over `data` against an X.509 DER public key. Ordinary
  invalid signatures return false. Options have the same PSS and concrete-key
  meaning as pkey-sign, and native resources are released on every exit path."
  ([md-fn pub-der data sig] (pkey-verify md-fn pub-der data sig nil nil))
  ([md-fn pub-der data sig want-algo] (pkey-verify md-fn pub-der data sig want-algo nil))
  ([md-fn pub-der data sig want-algo options]
   (with-der-key c-d2i-pubkey pub-der
     (fn [pkey]
       (check-signature-options pkey want-algo options)
       (let [data (as-ba data) sig (as-ba sig) dn (alength data) sn (alength sig)
             ctx (c-md-ctx-new)]
         (when (ffi/null? ctx)
           (throw (ex-info "verification context allocation failed" {})))
         (try
           (with-ptrs [data sig]
             (fn [dp sp]
               (let [pctxp (ffi/alloc ptr-size)]
                 (try
                   (ffi/write pctxp :pointer ffi/null 0)
                   (when (not= 1 (c-dgst-verify-init ctx pctxp (if md-fn (md-fn) ffi/null) ffi/null pkey))
                     (throw (ex-info "verification init failed" {})))
                   (when (:pss options)
                     (configure-pss! (ffi/read pctxp :pointer) md-fn))
                   ;; a bad signature is a false, not a throw
                   (let [result (c-dgst-verify ctx sp sn dp dn)]
                     (when (not= 1 result)
                       (c-err-clear))
                     (= 1 result))
                   (finally
                     ;; DigestVerifyInit transferred pctx ownership to ctx.
                     (ffi/free pctxp))))))
           (finally (c-md-ctx-free ctx))))))))

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
             :key-type (pkey-type pkey)
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
    ;; Bouncy Castle's SHA*withRSAandMGF1 uses MGF1 with the same digest and a
    ;; digest-length salt. OpenSSL needs all three PSS controls set explicitly.
    "SHA512WITHRSAANDMGF1" [c-sha512 "RSA" {:pss true}]
    "SHA384WITHRSAANDMGF1" [c-sha384 "RSA" {:pss true}]
    "SHA256WITHRSAANDMGF1" [c-sha256 "RSA" {:pss true}]
    ;; PureEdDSA hashes internally: no digest, one-shot over the whole message.
    ;; Generic EdDSA accepts either curve; concrete names enforce theirs.
    "ED25519"         [nil "EdDSA" {:key-type "Ed25519"}]
    "ED448"           [nil "EdDSA" {:key-type "Ed448"}]
    "EDDSA"           [nil "EdDSA"]
    (throw (ex-info (str "unsupported Signature algorithm: " algo) {:algo algo}))))

(defn- digest-spec [algo]
  (case (str/upper-case (str algo)) ("SHA-512" "SHA512") [c-sha512 64] ("SHA-384" "SHA384") [c-sha384 48]
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
(defn- x509-public-key? [x] (and (table? x) (= :jolt.crypto/public-key (tget x :jolt/type))))

(defn certificate-subject
  "Return an X.509 subject in certificate RDN order, as Buddy's X500Name does."
  [cert]
  (when-not (x509-cert? cert)
    (throw (ex-info "Unknown certificate type" {:kind (class cert)})))
  (str/join "," (reverse (split-rdns (tget cert :subject)))))

(defn verify-certificate-signature
  "Verify a parsed X.509 value with a tagged public key or issuer certificate."
  [cert public-key]
  (when-not (x509-cert? cert)
    (throw (ex-info "Unknown certificate type" {:kind (class cert)})))
  (cond
    (x509-public-key? public-key)
    (openssl/x509-verify (tget cert :der) (tget public-key :bytes))

    (x509-cert? public-key)
    (openssl/x509-verify (tget cert :der) (:der (tget public-key :public-key)))

    :else
    (throw (ex-info "Unknown public key type" {:kind (class public-key)}))))

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
     "doFinal" (fn [self data & more]
                 (let [d (if (= 2 (count more))
                           (ba-window data (first more) (second more))
                           data)]
                   (aes-cbc (= ENCRYPT-MODE (tget self :mode)) (tget self :key) (tget self :iv) d)))
     "getIV" (fn [self] (tget self :iv))
     "getBlockSize" (fn [self] 16)})

  ;; javax.crypto.Mac
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

  ;; java.security.MessageDigest
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
                         ;; the JDK's EdDSA generator defaults to Ed25519
                         ("ED25519" "EDDSA") (doto (tt :jolt.crypto/keypair-gen) (tput! :algo "EdDSA"))
                         (throw (ex-info (str "unsupported KeyPairGenerator algorithm: " algo) {:algo algo}))))}))
  (__register-class-methods! :jolt.crypto/keypair-gen
    {;; initialize(AlgorithmParameterSpec) names the curve; initialize(int) gives
     ;; a key size in bits, which for EC selects the P-curve of that size and
     ;; for RSA is the modulus length. The curve is resolved here rather than at
     ;; generate time because that is where the JDK rejects an unknown one.
     "initialize" (fn [self spec & _]
                    (cond
                      ;; Ed25519 has one size: 255 bits, as the JDK takes it
                      (= "EdDSA" (tget self :algo))
                      (when-not (and (not (table? spec)) (= 255 (long spec)))
                        (throw (ex-info (str "unsupported EdDSA parameter: " spec) {:spec spec})))

                      (= "RSA" (tget self :algo))
                      (do
                        (when (table? spec)
                          (throw (ex-info (str "unsupported RSA parameter: " spec) {:spec spec})))
                        (let [bits (long spec)]
                          (when-not (<= 512 bits 16384)
                            (throw (ex-info (str "RSA key size must be between 512 and 16384 bits, got " bits)
                                            {:bits bits})))
                          (tput! self :bits bits)))
                      :else
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
                              (tput! :algo (tget self :algo))
                              (tput! :key-type (tget self :key-type))))
     "getPrivate" (fn [self] (doto (tt :jolt.crypto/private-key)
                               (tput! :bytes (tget self :private))
                               (tput! :algo (tget self :algo))
                               (tput! :key-type (tget self :key-type))))})

  ;; java.security.KeyFactory — DER key spec in, key object out. Decoding once
  ;; here means malformed bytes are rejected at generate* time, as on the JVM,
  ;; rather than surfacing later as a mysterious verification failure. The
  ;; decoded key's own OpenSSL type — not the algorithm the factory was asked
  ;; for or a filename — is what the key gets stamped with,
  ;; and a disagreement between the two is an error, as it is on the JVM.
  (doseq [nm ["KeyFactory" "java.security.KeyFactory"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (case (str/upper-case (str algo))
                         "EC" (doto (tt :jolt.crypto/key-factory) (tput! :algo "EC"))
                         "RSA" (doto (tt :jolt.crypto/key-factory) (tput! :algo "RSA"))
                         "DSA" (doto (tt :jolt.crypto/key-factory) (tput! :algo "DSA"))
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

  ;; java.security.Signature — stateful like Cipher: init picks key and
  ;; direction, update accumulates, sign/verify consume and reset.
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
                      (let [{:keys [algorithm key-type der]} (tget self :public-key)]
                        (doto (tt :jolt.crypto/public-key)
                          (tput! :bytes der)
                          (tput! :algo algorithm)
                          (tput! :key-type key-type))))
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
