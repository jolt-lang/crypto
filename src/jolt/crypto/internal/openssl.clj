(ns jolt.crypto.internal.openssl
  (:require [jolt.crypto.bytes :as bytes]
            [jolt.ffi :as ffi]))

(ffi/defcfn c-get-digest "EVP_get_digestbyname" [:string] :pointer)
(ffi/defcfn c-fetch-digest "EVP_MD_fetch" [:pointer :string :pointer] :pointer)
(ffi/defcfn c-free-digest "EVP_MD_free" [:pointer] :void)
(ffi/defcfn c-digest-size "EVP_MD_get_size" [:pointer] :int)
(ffi/defcfn c-digest "EVP_Digest" [:pointer :size_t :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-hmac "HMAC" [:pointer :pointer :int :pointer :size_t :pointer :pointer] :pointer)
(ffi/defcfn c-pbkdf2-hmac "PKCS5_PBKDF2_HMAC" [:pointer :int :pointer :int :int :pointer :int :pointer] :int :blocking)
(ffi/defcfn c-aes-128-ecb "EVP_aes_128_ecb" [] :pointer)
(ffi/defcfn c-aes-192-ecb "EVP_aes_192_ecb" [] :pointer)
(ffi/defcfn c-aes-256-ecb "EVP_aes_256_ecb" [] :pointer)
(ffi/defcfn c-aes-128-cbc "EVP_aes_128_cbc" [] :pointer)
(ffi/defcfn c-aes-192-cbc "EVP_aes_192_cbc" [] :pointer)
(ffi/defcfn c-aes-256-cbc "EVP_aes_256_cbc" [] :pointer)
(ffi/defcfn c-aes-128-ctr "EVP_aes_128_ctr" [] :pointer)
(ffi/defcfn c-aes-192-ctr "EVP_aes_192_ctr" [] :pointer)
(ffi/defcfn c-aes-256-ctr "EVP_aes_256_ctr" [] :pointer)
(ffi/defcfn c-aes-128-ofb "EVP_aes_128_ofb" [] :pointer)
(ffi/defcfn c-aes-192-ofb "EVP_aes_192_ofb" [] :pointer)
(ffi/defcfn c-aes-256-ofb "EVP_aes_256_ofb" [] :pointer)
(ffi/defcfn c-aes-128-gcm "EVP_aes_128_gcm" [] :pointer)
(ffi/defcfn c-aes-192-gcm "EVP_aes_192_gcm" [] :pointer)
(ffi/defcfn c-aes-256-gcm "EVP_aes_256_gcm" [] :pointer)
(ffi/defcfn c-aes-set-encrypt-key "AES_set_encrypt_key" [:pointer :int :pointer] :int)
(ffi/defcfn c-aes-set-decrypt-key "AES_set_decrypt_key" [:pointer :int :pointer] :int)
(ffi/defcfn c-aes-wrap-key "AES_wrap_key" [:pointer :pointer :pointer :pointer :uint] :int)
(ffi/defcfn c-aes-unwrap-key "AES_unwrap_key" [:pointer :pointer :pointer :pointer :uint] :int)
(ffi/defcfn c-chacha20 "EVP_chacha20" [] :pointer)
(ffi/defcfn c-cipher-ctx-new "EVP_CIPHER_CTX_new" [] :pointer)
(ffi/defcfn c-cipher-ctrl "EVP_CIPHER_CTX_ctrl" [:pointer :int :int :pointer] :int)
(ffi/defcfn c-cipher-ctx-free "EVP_CIPHER_CTX_free" [:pointer] :void)
(ffi/defcfn c-encrypt-init "EVP_EncryptInit_ex" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-encrypt-update "EVP_EncryptUpdate" [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-encrypt-final "EVP_EncryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-decrypt-init "EVP_DecryptInit_ex" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-decrypt-update "EVP_DecryptUpdate" [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-decrypt-final "EVP_DecryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-cipher-set-padding "EVP_CIPHER_CTX_set_padding" [:pointer :int] :int)
(ffi/defcfn c-pkey-new-mac-key "EVP_PKEY_new_mac_key" [:int :pointer :pointer :int] :pointer)
(ffi/defcfn c-pkey-free "EVP_PKEY_free" [:pointer] :void)
(ffi/defcfn c-d2i-pubkey "d2i_PUBKEY" [:pointer :pointer :long] :pointer)
(ffi/defcfn c-d2i-x509 "d2i_X509" [:pointer :pointer :long] :pointer)
(ffi/defcfn c-x509-free "X509_free" [:pointer] :void)
(ffi/defcfn c-x509-verify "X509_verify" [:pointer :pointer] :int)
(ffi/defcfn c-err-clear "ERR_clear_error" [] :void)
(ffi/defcfn c-md-ctx-new "EVP_MD_CTX_new" [] :pointer)
(ffi/defcfn c-md-ctx-free "EVP_MD_CTX_free" [:pointer] :void)
(ffi/defcfn c-digest-init "EVP_DigestInit_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-digest-update "EVP_DigestUpdate" [:pointer :pointer :size_t] :int)
(ffi/defcfn c-digest-final "EVP_DigestFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-hmac-ctx-new "HMAC_CTX_new" [] :pointer)
(ffi/defcfn c-hmac-ctx-free "HMAC_CTX_free" [:pointer] :void)
(ffi/defcfn c-hmac-init "HMAC_Init_ex" [:pointer :pointer :int :pointer :pointer] :int)
(ffi/defcfn c-hmac-update "HMAC_Update" [:pointer :pointer :size_t] :int)
(ffi/defcfn c-hmac-final "HMAC_Final" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-poly1305-sign-init "EVP_DigestSignInit" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-poly1305-sign "EVP_DigestSign" [:pointer :pointer :pointer :pointer :size_t] :int)

(def ^:private evp-pkey-poly1305 1061)
(def ^:private evp-ctrl-aead-set-ivlen 0x9)
(def ^:private evp-ctrl-aead-get-tag 0x10)
(def ^:private evp-ctrl-aead-set-tag 0x11)

(def ^:private digest-names
  {:md5 "MD5"
   :sha1 "SHA1"
   :sha256 "SHA256"
   :sha384 "SHA384"
   :sha512 "SHA512"
   :sha3-256 "SHA3-256"
   :sha3-384 "SHA3-384"
   :sha3-512 "SHA3-512"
   :blake2b-512 "BLAKE2B-512"
   :ripemd160 "RIPEMD160"})

(defn- unsupported-algorithm [algorithm]
  (throw (ex-info (str "Unsupported digest algorithm: " algorithm)
                  {:algorithm algorithm})))

(def ^:private provided-digests (atom {}))

(defn- provided?
  "Whether a loaded provider implements digest-name. EVP_get_digestbyname
  answers from a static table, so on OpenSSL 3.0.0-3.0.6 it hands back
  RIPEMD160 although only the legacy provider, which this library never loads,
  implements it there; using it then fails deep inside EVP_Digest or HMAC."
  [digest-name]
  (let [cached (get @provided-digests digest-name ::unknown)]
    (if (= ::unknown cached)
      (let [md (c-fetch-digest ffi/null digest-name ffi/null)
            found (not (ffi/null? md))]
        (if found (c-free-digest md) (c-err-clear))
        (swap! provided-digests assoc digest-name found)
        found)
      cached)))

(defn digest-available?
  "Whether this host's OpenSSL computes algorithm. :ripemd160 needs OpenSSL
  3.0.7 or later, which moved it back into the default provider."
  [algorithm]
  (boolean (some-> (get digest-names algorithm) provided?)))

(defn- digest-md [algorithm]
  (let [digest-name (get digest-names algorithm)]
    (when-not (and digest-name (provided? digest-name))
      (unsupported-algorithm algorithm))
    (let [md (c-get-digest digest-name)]
      (when (ffi/null? md)
        (unsupported-algorithm algorithm))
      md)))

(defn- md-size [algorithm md]
  (let [size (c-digest-size md)]
    (when-not (pos? size)
      (throw (ex-info (str "OpenSSL could not size digest: " algorithm)
                      {:algorithm algorithm :size size})))
    size))

(defn digest-length [algorithm]
  (md-size algorithm (digest-md algorithm)))

(defn- as-bytes [value]
  (if (bytes/bytes? value)
    value
    (byte-array value)))

(defn- with-byte-ptrs [byte-arrays f]
  (let [ptrs (atom [])]
    (try
      (doseq [data byte-arrays]
        (let [ptr (ffi/alloc (max 1 (alength data)))]
          (swap! ptrs conj ptr)
          (ffi/write-array ptr data)))
      (apply f @ptrs)
      (finally
        (doseq [ptr @ptrs]
          (ffi/free ptr))))))

(defn- with-der-object [decode-fn free-fn der kind f]
  (let [der (as-bytes der)
        length (alength der)
        buffer (ffi/alloc (max 1 length))]
    (try
      (let [holder (ffi/alloc (ffi/sizeof :pointer))]
        (try
          (ffi/write-array buffer der)
          (ffi/write holder :pointer buffer 0)
          (c-err-clear)
          (let [object (decode-fn ffi/null holder length)]
            (when (ffi/null? object)
              (c-err-clear)
              (throw (ex-info (str "OpenSSL could not decode " (name kind)) {:kind kind})))
            (try
              (f object)
              (finally
                (free-fn object))))
          (finally
            (ffi/free holder))))
      (finally
        (ffi/free buffer)))))

(defn x509-verify
  "Verify certificate DER against a SubjectPublicKeyInfo DER key."
  [certificate-der public-key-der]
  (with-der-object c-d2i-x509 c-x509-free certificate-der :certificate
    (fn [certificate]
      (with-der-object c-d2i-pubkey c-pkey-free public-key-der :public-key
        (fn [public-key]
          (c-err-clear)
          (let [result (c-x509-verify certificate public-key)]
            (c-err-clear)
            (cond
              (= 1 result) true
              (zero? result) false
              :else (throw (ex-info "OpenSSL X.509 signature verification failed"
                                    {:result result})))))))))

(defn digest-bytes [algorithm data]
  (let [md (digest-md algorithm)
        length (md-size algorithm md)
        data (as-bytes data)]
    (with-byte-ptrs [data]
      (fn [data-ptr]
        (let [output (ffi/alloc 64)]
          (try
            (let [output-length (ffi/alloc 4)]
              (try
                (when-not (= 1 (c-digest data-ptr (alength data) output output-length md ffi/null))
                  (throw (ex-info (str "OpenSSL digest failed: " algorithm)
                                  {:algorithm algorithm})))
                (let [actual-length (ffi/read output-length :int)]
                  (when-not (= length actual-length)
                    (throw (ex-info (str "OpenSSL returned an unexpected digest length: " algorithm)
                                    {:algorithm algorithm :expected length :actual actual-length})))
                  (ffi/read-array output actual-length))
                (finally
                  (ffi/free output-length))))
            (finally
              (ffi/free output))))))))

(defn hmac-bytes [algorithm key data]
  (let [md (digest-md algorithm)
        length (md-size algorithm md)
        key (as-bytes key)
        data (as-bytes data)]
    (with-byte-ptrs [key data]
      (fn [key-ptr data-ptr]
        (let [output (ffi/alloc 64)]
          (try
            (let [result (c-hmac md key-ptr (alength key)
                                 data-ptr (alength data) output ffi/null)]
              (when (ffi/null? result)
                (throw (ex-info (str "OpenSSL HMAC failed: " algorithm)
                                {:algorithm algorithm})))
              (ffi/read-array output length))
            (finally
              (ffi/free output))))))))

(defn pbkdf2-bytes [algorithm key salt iterations length]
  (let [md (digest-md algorithm)
        key (as-bytes key)
        salt (as-bytes salt)]
    (when-not (and (integer? iterations) (<= 1 iterations 2147483647))
      (throw (ex-info "PBKDF2 iterations must be a positive 32-bit integer"
                      {:iterations iterations})))
    (when-not (and (integer? length) (<= 0 length 2147483647))
      (throw (ex-info "PBKDF2 output length must be a non-negative 32-bit integer"
                      {:length length})))
    (if (zero? length)
      (byte-array 0)
      (with-byte-ptrs [key salt]
        (fn [key-ptr salt-ptr]
          (let [output (ffi/alloc length)]
            (try
              (when-not (= 1 (c-pbkdf2-hmac key-ptr (alength key) salt-ptr (alength salt)
                                            iterations md length output))
                (throw (ex-info (str "OpenSSL PBKDF2 failed: " algorithm)
                                {:algorithm algorithm})))
              (ffi/read-array output length)
              (finally
                (ffi/free output)))))))))

(defn- aes-key-wrap [op input secret]
  (let [input (as-bytes input)
        secret (as-bytes secret)
        input-length (alength input)
        secret-length (alength secret)
        wrapping? (= :wrap op)
        minimum (if wrapping? 16 24)
        output-length (if wrapping? (+ input-length 8) (- input-length 8))]
    (when-not (#{16 24 32} secret-length)
      (throw (ex-info "AES key-wrap KEK must be 16, 24, or 32 bytes"
                      {:key-length secret-length :op op})))
    (when-not (and (>= input-length minimum) (zero? (mod input-length 8)))
      (throw (ex-info (str "AES key-wrap input must be a multiple of 8 bytes and at least " minimum)
                      {:input-length input-length :op op})))
    (with-byte-ptrs [input secret]
      (fn [input-ptr secret-ptr]
        ;; OpenSSL's AES_KEY is 60 32-bit round-key words plus an int rounds.
        (let [aes-key (ffi/alloc 256)
              output (ffi/alloc (max 1 output-length))]
          (try
            (let [set-key (if wrapping? c-aes-set-encrypt-key c-aes-set-decrypt-key)]
              (when-not (zero? (set-key secret-ptr (* 8 secret-length) aes-key))
                (throw (ex-info "OpenSSL AES key-wrap key initialization failed" {:op op}))))
            (let [wrap-fn (if wrapping? c-aes-wrap-key c-aes-unwrap-key)
                  actual-length (wrap-fn aes-key ffi/null output input-ptr input-length)]
              (when-not (= output-length actual-length)
                (throw (ex-info "OpenSSL AES key wrap failed integrity or length validation"
                                {:op op :expected output-length :actual actual-length})))
              (ffi/read-array output actual-length))
            (finally
              (ffi/free aes-key)
              (ffi/free output))))))))

(defn aes-wrap
  "Wrap a multiple-of-8 key with RFC 3394 AES Key Wrap."
  [input secret]
  (aes-key-wrap :wrap input secret))

(defn aes-unwrap
  "Authenticate and unwrap an RFC 3394 wrapped key."
  [input secret]
  (aes-key-wrap :unwrap input secret))

(def ^:private aes-ciphers
  {:ecb {16 c-aes-128-ecb 24 c-aes-192-ecb 32 c-aes-256-ecb}
   :cbc {16 c-aes-128-cbc 24 c-aes-192-cbc 32 c-aes-256-cbc}
   :ctr {16 c-aes-128-ctr 24 c-aes-192-ctr 32 c-aes-256-ctr}
   :ofb {16 c-aes-128-ofb 24 c-aes-192-ofb 32 c-aes-256-ofb}
   :gcm {16 c-aes-128-gcm 24 c-aes-192-gcm 32 c-aes-256-gcm}})

(defn- cipher-operations [op]
  (case op
    :encrypt [c-encrypt-init c-encrypt-update c-encrypt-final]
    :decrypt [c-decrypt-init c-decrypt-update c-decrypt-final]
    (throw (ex-info (str "Unsupported cipher operation: " op) {:op op}))))

(defn- cipher-aad! [ctx op aad]
  (let [[_ update _] (cipher-operations op)
        aad (as-bytes aad)]
    (with-byte-ptrs [aad]
      (fn [aad-ptr]
        (let [output-length (ffi/alloc 4)]
          (try
            (when-not (= 1 (update ctx ffi/null output-length aad-ptr (alength aad)))
              (throw (ex-info "OpenSSL GCM AAD update failed" {:op op})))
            (finally
              (ffi/free output-length))))))))

(defn cipher-context
  "Create an initialized, unpadding EVP context for a Buddy low-level engine."
  ([algorithm mode op key iv]
   (cipher-context algorithm mode op key iv {}))
  ([algorithm mode op key iv {:keys [aad]}]
   (let [key (as-bytes key)
         iv (when (some? iv) (as-bytes iv))
         mode (if (= :sic mode) :ctr mode)
         key-length (alength key)
         iv-length (count iv)]
     (when (and (= :chacha algorithm) (not= 32 key-length))
       (throw (ex-info "ChaCha key must be 32 bytes" {:key-length key-length})))
     (when (= :aes algorithm)
       (when-not (#{16 24 32} key-length)
         (throw (ex-info "AES key must be 16, 24, or 32 bytes"
                         {:key-length key-length})))
       (when (and (= :ecb mode) (some? iv))
         (throw (ex-info "ECB mode does not use an IV" {:mode :ecb})))
       (when (and (not= :ecb mode) (not= :gcm mode) (not= 16 iv-length))
         (throw (ex-info "AES IV must be 16 bytes" {:iv-length iv-length})))
       (when (and (= :gcm mode) (not (pos? iv-length)))
         (throw (ex-info "AES-GCM IV must not be empty" {:iv-length iv-length}))))
     (when (and (= :chacha algorithm) (not= 8 iv-length))
       (throw (ex-info "ChaCha nonce must be 8 bytes" {:iv-length iv-length})))
     (let [cipher-fn (case algorithm
                       :aes (or (get-in aes-ciphers [mode key-length])
                                (throw (ex-info (str "Unsupported AES mode: " mode)
                                                {:algorithm algorithm :mode mode})))
                       :chacha c-chacha20
                       (throw (ex-info (str "Unsupported cipher algorithm: " algorithm)
                                       {:algorithm algorithm})))
           native-iv (if (= :chacha algorithm)
                       (bytes/concat (byte-array 8) iv)
                       iv)
           inputs (if native-iv [key native-iv] [key])
           [init _ _] (cipher-operations op)
           ctx (c-cipher-ctx-new)]
       (when (ffi/null? ctx)
         (throw (ex-info "OpenSSL cipher context allocation failed"
                         {:algorithm algorithm :mode mode})))
       (try
         (with-byte-ptrs inputs
           (fn [& ptrs]
             (let [key-ptr (first ptrs)
                   iv-ptr (or (second ptrs) ffi/null)]
               (if (= :gcm mode)
                 (do
                   (when-not (= 1 (init ctx (cipher-fn) ffi/null ffi/null ffi/null))
                     (throw (ex-info "OpenSSL GCM cipher initialization failed"
                                     {:algorithm algorithm :mode mode :op op})))
                   (when-not (= 1 (c-cipher-ctrl ctx evp-ctrl-aead-set-ivlen
                                                 iv-length ffi/null))
                     (throw (ex-info "OpenSSL GCM IV length configuration failed"
                                     {:iv-length iv-length})))
                   (when-not (= 1 (init ctx ffi/null ffi/null key-ptr iv-ptr))
                     (throw (ex-info "OpenSSL GCM key initialization failed"
                                     {:algorithm algorithm :mode mode :op op}))))
                 (do
                   (when-not (= 1 (init ctx (cipher-fn) ffi/null key-ptr iv-ptr))
                     (throw (ex-info "OpenSSL cipher initialization failed"
                                     {:algorithm algorithm :mode mode :op op})))
                   (when-not (= 1 (c-cipher-set-padding ctx 0))
                     (throw (ex-info "OpenSSL cipher padding configuration failed"
                                     {:algorithm algorithm :mode mode}))))))))
         (when (= :gcm mode)
           (cipher-aad! ctx op (or aad (byte-array 0))))
         ctx
         (catch Exception e
           (c-cipher-ctx-free ctx)
           (throw e)))))))

(defn free-cipher-context!
  "Detach and release an engine's native context, if present."
  [holder]
  (when-let [ctx @holder]
    (reset! holder nil)
    (c-cipher-ctx-free ctx))
  nil)

(defn cipher-update
  "Process exactly one input window and return the same number of bytes."
  [ctx op input]
  (let [input (as-bytes input)
        length (alength input)
        [_ update _] (cipher-operations op)]
    (with-byte-ptrs [input]
      (fn [input-ptr]
        (let [output (ffi/alloc (max 1 (+ length 16)))]
          (try
            (let [output-length (ffi/alloc 4)]
              (try
                (when-not (= 1 (update ctx output output-length input-ptr length))
                  (throw (ex-info "OpenSSL cipher update failed" {:op op})))
                (let [actual-length (ffi/read output-length :int)]
                  (when-not (= length actual-length)
                    (throw (ex-info "OpenSSL cipher returned an unexpected output length"
                                    {:op op :expected length :actual actual-length})))
                  (ffi/read-array output actual-length))
                (finally
                  (ffi/free output-length))))
            (finally
              (ffi/free output))))))))

(defn cipher-final
  "Finalize a non-AEAD EVP context, which must not emit additional bytes."
  [ctx op]
  (let [[_ _ final] (cipher-operations op)
        output (ffi/alloc 16)]
    (try
      (let [output-length (ffi/alloc 4)]
        (try
          (when-not (= 1 (final ctx output output-length))
            (throw (ex-info "OpenSSL cipher finalization failed" {:op op})))
          (let [actual-length (ffi/read output-length :int)]
            (when-not (zero? actual-length)
              (throw (ex-info "Non-AEAD cipher finalization emitted bytes"
                              {:op op :actual actual-length})))
            0)
          (finally
            (ffi/free output-length))))
      (finally
        (ffi/free output)))))

(defn gcm-final
  "Finalize GCM, returning the 128-bit tag on encryption and zero on decryption."
  [ctx op expected-tag]
  (let [[_ _ final] (cipher-operations op)
        output (ffi/alloc 16)]
    (try
      (let [output-length (ffi/alloc 4)]
        (try
          (when (= :decrypt op)
            (when-not (= 16 (count expected-tag))
              (throw (ex-info "GCM ciphertext must end with a 128-bit authentication tag"
                              {:tag-length (count expected-tag)})))
            (with-byte-ptrs [expected-tag]
              (fn [tag-ptr]
                (when-not (= 1 (c-cipher-ctrl ctx evp-ctrl-aead-set-tag 16 tag-ptr))
                  (throw (ex-info "OpenSSL GCM tag configuration failed" {:op op}))))))
          (when-not (= 1 (final ctx output output-length))
            (throw (ex-info "OpenSSL GCM finalization failed" {:op op})))
          (when-not (zero? (ffi/read output-length :int))
            (throw (ex-info "GCM finalization emitted unexpected bytes" {:op op})))
          (if (= :encrypt op)
            (let [tag (ffi/alloc 16)]
              (try
                (when-not (= 1 (c-cipher-ctrl ctx evp-ctrl-aead-get-tag 16 tag))
                  (throw (ex-info "OpenSSL GCM tag extraction failed" {:op op})))
                (ffi/read-array tag 16)
                (finally
                  (ffi/free tag))))
            0)
          (finally
            (ffi/free output-length))))
      (finally
        (ffi/free output)))))

(defn- aes-128-ecb-block [key block]
  (with-byte-ptrs [key block]
    (fn [key-ptr block-ptr]
      (let [ctx (c-cipher-ctx-new)]
        (when (ffi/null? ctx)
          (throw (ex-info "OpenSSL AES context allocation failed" {})))
        (try
          (let [output (ffi/alloc 16)]
            (try
              (let [output-length (ffi/alloc 4)]
                (try
                  (when-not (= 1 (c-encrypt-init ctx (c-aes-128-ecb) ffi/null key-ptr ffi/null))
                    (throw (ex-info "OpenSSL AES-128-ECB initialization failed" {})))
                  (when-not (= 1 (c-cipher-set-padding ctx 0))
                    (throw (ex-info "OpenSSL AES padding configuration failed" {})))
                  (when-not (= 1 (c-encrypt-update ctx output output-length block-ptr 16))
                    (throw (ex-info "OpenSSL AES-128-ECB update failed" {})))
                  (let [update-length (ffi/read output-length :int)]
                    (when-not (= 1 (c-encrypt-final ctx (+ output update-length) output-length))
                      (throw (ex-info "OpenSSL AES-128-ECB finalization failed" {})))
                    (let [actual-length (+ update-length (ffi/read output-length :int))]
                      (when-not (= 16 actual-length)
                        (throw (ex-info "OpenSSL AES-128-ECB returned an unexpected block length"
                                        {:expected 16 :actual actual-length})))
                      (ffi/read-array output actual-length)))
                  (finally
                    (ffi/free output-length))))
              (finally
                (ffi/free output))))
          (finally
            (c-cipher-ctx-free ctx)))))))

(defn- poly1305-bytes [key data]
  (with-byte-ptrs [key data]
    (fn [key-ptr data-ptr]
      (let [pkey (c-pkey-new-mac-key evp-pkey-poly1305 ffi/null key-ptr 32)]
        (when (ffi/null? pkey)
          (throw (ex-info "OpenSSL Poly1305 key initialization failed" {})))
        (try
          (let [ctx (c-md-ctx-new)]
            (when (ffi/null? ctx)
              (throw (ex-info "OpenSSL Poly1305 context allocation failed" {})))
            (try
              (let [output (ffi/alloc 16)]
                (try
                  (let [output-length (ffi/alloc 8)]
                    (try
                      (when-not (= 1 (c-poly1305-sign-init ctx ffi/null ffi/null ffi/null pkey))
                        (throw (ex-info "OpenSSL Poly1305 initialization failed" {})))
                      (ffi/write output-length :size_t 16 0)
                      (when-not (= 1 (c-poly1305-sign ctx output output-length data-ptr (alength data)))
                        (throw (ex-info "OpenSSL Poly1305 signing failed" {})))
                      (let [actual-length (ffi/read output-length :size_t)]
                        (when-not (= 16 actual-length)
                          (throw (ex-info "OpenSSL Poly1305 returned an unexpected tag length"
                                          {:expected 16 :actual actual-length})))
                        (ffi/read-array output actual-length))
                      (finally
                        (ffi/free output-length))))
                  (finally
                    (ffi/free output))))
              (finally
                (c-md-ctx-free ctx))))
          (finally
            (c-pkey-free pkey)))))))

(defn poly1305-aes-bytes [key iv data]
  (let [key (as-bytes key)
        iv (as-bytes iv)
        data (as-bytes data)]
    (when-not (= 32 (alength key))
      (throw (ex-info "Poly1305 key must be 32 bytes" {:key-length (alength key)})))
    (when-not (= 16 (alength iv))
      (throw (ex-info "Poly1305 IV must be 16 bytes" {:iv-length (alength iv)})))
    (let [r (bytes/slice key 0 16)]
      (doseq [index [3 7 11 15]]
        (aset-byte r index (unchecked-byte (bit-and (aget r index) 15))))
      (doseq [index [4 8 12]]
        (aset-byte r index (unchecked-byte (bit-and (aget r index) 252))))
      (let [pad (aes-128-ecb-block (bytes/slice key 16 32) iv)]
        (poly1305-bytes (bytes/concat r pad) data)))))

;; Incremental digest and HMAC contexts, for engines that stream: each update
;; goes straight into OpenSSL, so hashing a large file runs in constant memory.
;; A context is native memory with no finalizer; finish-* and free-* release it.

(defn- feed! [update-fn ctx data what algorithm]
  (with-byte-ptrs [data]
    (fn [data-ptr]
      (when-not (= 1 (update-fn ctx data-ptr (alength data)))
        (throw (ex-info (str "OpenSSL " what " update failed: " algorithm)
                        {:algorithm algorithm}))))))

(defn- finish! [final-fn ctx algorithm what]
  (let [md (digest-md algorithm)
        length (md-size algorithm md)
        output (ffi/alloc 64)
        output-length (ffi/alloc 4)]
    (try
      (when-not (= 1 (final-fn ctx output output-length))
        (throw (ex-info (str "OpenSSL " what " failed: " algorithm) {:algorithm algorithm})))
      (ffi/read-array output length)
      (finally
        (ffi/free output-length)
        (ffi/free output)))))

(defn digest-context
  "A new incremental digest context for algorithm."
  [algorithm]
  (let [md (digest-md algorithm)
        ctx (c-md-ctx-new)]
    (when (ffi/null? ctx)
      (throw (ex-info "OpenSSL could not allocate a digest context" {:algorithm algorithm})))
    (when-not (= 1 (c-digest-init ctx md ffi/null))
      (c-md-ctx-free ctx)
      (throw (ex-info (str "OpenSSL digest failed: " algorithm) {:algorithm algorithm})))
    ctx))

(defn digest-update! [ctx algorithm data]
  (feed! c-digest-update ctx (as-bytes data) "digest" algorithm))

(defn digest-finish!
  "Finalize ctx, free it and return the digest."
  [ctx algorithm]
  (try
    (finish! c-digest-final ctx algorithm "digest")
    (finally
      (c-md-ctx-free ctx))))

(defn free-digest-context! [ctx]
  (c-md-ctx-free ctx))

(defn hmac-context
  "A new incremental HMAC context for algorithm keyed with key."
  [algorithm key]
  (let [md (digest-md algorithm)
        key (as-bytes key)
        ctx (c-hmac-ctx-new)]
    (when (ffi/null? ctx)
      (throw (ex-info "OpenSSL could not allocate an HMAC context" {:algorithm algorithm})))
    (with-byte-ptrs [key]
      (fn [key-ptr]
        (when-not (= 1 (c-hmac-init ctx key-ptr (alength key) md ffi/null))
          (c-hmac-ctx-free ctx)
          (throw (ex-info (str "OpenSSL HMAC failed: " algorithm) {:algorithm algorithm})))))
    ctx))

(defn hmac-update! [ctx algorithm data]
  (feed! c-hmac-update ctx (as-bytes data) "HMAC" algorithm))

(defn hmac-finish!
  "Finalize ctx, free it and return the MAC."
  [ctx algorithm]
  (try
    (finish! c-hmac-final ctx algorithm "HMAC")
    (finally
      (c-hmac-ctx-free ctx))))

(defn free-hmac-context! [ctx]
  (c-hmac-ctx-free ctx))
