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
  EVP picks the primitive from the key itself, so the same call serves both."
  [md-fn priv-der data]
  (with-der-key c-d2i-privkey priv-der
    (fn [pkey]
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
          (finally (c-md-ctx-free ctx) (ffi/free dp) (ffi/free lenp)))))))

(defn pkey-verify
  "Verify a signature over `data` against an X.509 DER public key, digesting
  with md-fn. The signature format is the key algorithm's (DER ECDSA r/s, raw
  PKCS#1 v1.5 RSA)."
  [md-fn pub-der data sig]
  (with-der-key c-d2i-pubkey pub-der
    (fn [pkey]
      (let [data (as-ba data) sig (as-ba sig) dn (alength data) sn (alength sig)
            ctx (c-md-ctx-new) dp (ffi/alloc (max 1 dn)) sp (ffi/alloc (max 1 sn))]
        (try
          (ffi/write-array dp data)
          (ffi/write-array sp sig)
          (when (not= 1 (c-dgst-verify-init ctx ffi/null (md-fn) ffi/null pkey))
            (throw (ex-info "verification init failed" {})))
          ;; a bad signature is a false, not a throw: EVP reports both the same way
          (= 1 (c-dgst-verify ctx sp sn dp dn))
          (finally (c-md-ctx-free ctx) (ffi/free dp) (ffi/free sp)))))))

;; --- algorithm name -> primitive --------------------------------------------
(defn- mac-md [algo]
  (case (str algo) ("HmacSHA512" "HMACSHA512") [c-sha512 64] ("HmacSHA384" "HMACSHA384") [c-sha384 48]
    ("HmacSHA256" "HMACSHA256") [c-sha256 32] ("HmacSHA1" "HMACSHA1") [c-sha1 20]
    (throw (ex-info (str "unsupported Mac algorithm: " algo) {:algo algo}))))
;; SHA256withECDSA, SHA256withRSA and friends. The JVM spells these without
;; separators and case-insensitively in practice, so match on the upcased form.
(defn- signature-md [algo]
  (case (str/upper-case (str algo))
    "SHA512WITHECDSA" c-sha512
    "SHA384WITHECDSA" c-sha384
    "SHA256WITHECDSA" c-sha256
    "SHA224WITHECDSA" c-sha224
    "SHA1WITHECDSA"   c-sha1
    "SHA512WITHRSA"   c-sha512
    "SHA384WITHRSA"   c-sha384
    "SHA256WITHRSA"   c-sha256
    "SHA224WITHRSA"   c-sha224
    "SHA1WITHRSA"     c-sha1
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
  ;; accepts either algorithm's DER, so the factory only needs to remember
  ;; which algorithm it was asked for, to stamp on the keys it hands out.
  (doseq [nm ["KeyFactory" "java.security.KeyFactory"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _]
                       (case (str/upper-case (str algo))
                         "EC" (doto (tt :jolt.crypto/key-factory) (tput! :algo "EC"))
                         "RSA" (doto (tt :jolt.crypto/key-factory) (tput! :algo "RSA"))
                         (throw (ex-info (str "unsupported KeyFactory algorithm: " algo) {:algo algo}))))}))
  (__register-class-methods! :jolt.crypto/key-factory
    {"generatePublic" (fn [self spec]
                        (let [der (->ba spec)]
                          (with-der-key c-d2i-pubkey der (fn [_] nil))
                          (doto (tt :jolt.crypto/public-key)
                            (tput! :bytes der) (tput! :algo (tget self :algo)))))
     "generatePrivate" (fn [self spec]
                         (let [der (->ba spec)]
                           (with-der-key c-d2i-privkey der (fn [_] nil))
                           (doto (tt :jolt.crypto/private-key)
                             (tput! :bytes der) (tput! :algo (tget self :algo)))))
     "getAlgorithm" (fn [self] (tget self :algo))})

  ;; java.security.Signature — stateful like Cipher: init picks key and
  ;; direction, update accumulates, sign/verify consume and reset.
  (doseq [nm ["Signature" "java.security.Signature"]]
    (__register-class-statics! nm
      {"getInstance" (fn [algo & _] (doto (tt :jolt.crypto/signature)
                                      (tput! :md (signature-md algo))
                                      (tput! :algo (str algo))
                                      (tput! :acc [])))}))
  (__register-class-methods! :jolt.crypto/signature
    {"initSign" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "initVerify" (fn [self key & _] (tput! self :key (->ba key)) (tput! self :acc []) nil)
     "update" (fn [self data & _]
                (tput! self :acc (conj (tget self :acc) (snapshot-ba data)))
                nil)
     "sign" (fn [self & _]
              (let [body (concat-bas (tget self :acc))]
                (tput! self :acc [])
                (pkey-sign (tget self :md) (tget self :key) body)))
     "verify" (fn [self sig & _]
                (let [body (concat-bas (tget self :acc))]
                  (tput! self :acc [])
                  (pkey-verify (tget self :md) (tget self :key) body sig)))
     "getAlgorithm" (fn [self] (tget self :algo))})
  nil)

(install!)
