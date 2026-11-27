(ns jolt.crypto.internal.openssl
  (:require [jolt.crypto.bytes :as bytes]
            [jolt.ffi :as ffi]))

(ffi/defcfn c-get-digest "EVP_get_digestbyname" [:string] :pointer)
(ffi/defcfn c-digest-size "EVP_MD_get_size" [:pointer] :int)
(ffi/defcfn c-digest "EVP_Digest" [:pointer :size_t :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-hmac "HMAC" [:pointer :pointer :int :pointer :size_t :pointer :pointer] :pointer)

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
