(ns jolt.crypto.internal.openssl
  (:require [jolt.crypto.bytes :as bytes]
            [jolt.ffi :as ffi]))

(ffi/defcfn c-get-digest "EVP_get_digestbyname" [:string] :pointer)
(ffi/defcfn c-digest-size "EVP_MD_get_size" [:pointer] :int)
(ffi/defcfn c-digest "EVP_Digest" [:pointer :size_t :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-hmac "HMAC" [:pointer :pointer :int :pointer :size_t :pointer :pointer] :pointer)
(ffi/defcfn c-pbkdf2-hmac "PKCS5_PBKDF2_HMAC" [:pointer :int :pointer :int :int :pointer :int :pointer] :int :blocking)
(ffi/defcfn c-aes-128-ecb "EVP_aes_128_ecb" [] :pointer)
(ffi/defcfn c-cipher-ctx-new "EVP_CIPHER_CTX_new" [] :pointer)
(ffi/defcfn c-cipher-ctx-free "EVP_CIPHER_CTX_free" [:pointer] :void)
(ffi/defcfn c-encrypt-init "EVP_EncryptInit_ex" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-encrypt-update "EVP_EncryptUpdate" [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-encrypt-final "EVP_EncryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-cipher-set-padding "EVP_CIPHER_CTX_set_padding" [:pointer :int] :int)
(ffi/defcfn c-pkey-new-mac-key "EVP_PKEY_new_mac_key" [:int :pointer :pointer :int] :pointer)
(ffi/defcfn c-pkey-free "EVP_PKEY_free" [:pointer] :void)
(ffi/defcfn c-md-ctx-new "EVP_MD_CTX_new" [] :pointer)
(ffi/defcfn c-md-ctx-free "EVP_MD_CTX_free" [:pointer] :void)
(ffi/defcfn c-poly1305-sign-init "EVP_DigestSignInit" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-poly1305-sign "EVP_DigestSign" [:pointer :pointer :pointer :pointer :size_t] :int)

(def ^:private evp-pkey-poly1305 1061)

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

(defn- digest-md [algorithm]
  (let [digest-name (get digest-names algorithm)]
    (when-not digest-name
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
