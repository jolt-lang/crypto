(ns jolt.crypto.internal.support
  "What jolt.crypto's shims and its internal namespaces share: the host
  tagged-table accessors, byte-array coercion and windowing, C buffers for byte
  arrays, DER output through i2d_*, memory BIOs, and an EVP_PKEY's type name."
  (:require [jolt.ffi :as ffi]))

;; OpenSSL 3 reports the decoded key's concrete type directly. This avoids
;; guessing from filenames or probing algorithm-specific getters.
(ffi/defcfn c-pkey-type-name "EVP_PKEY_get0_type_name" [:pointer] :pointer)

;; Memory BIOs: certificates and PEM keys are read from one, and X509_NAME
;; prints into one.

(ffi/defcfn c-bio-new-mem-buf  "BIO_new_mem_buf"         [:pointer :int] :pointer)
(ffi/defcfn c-bio-new          "BIO_new"                 [:pointer] :pointer)
(ffi/defcfn c-bio-s-mem        "BIO_s_mem"               [] :pointer)
(ffi/defcfn c-bio-read         "BIO_read"                [:pointer :pointer :int] :int)
(ffi/defcfn c-bio-free         "BIO_free"                [:pointer] :int)

;; --- tagged tables and byte arrays ------------------------------------------
(defn tt [tag] (jolt.host/tagged-table tag))
(defn tget [t k] (jolt.host/ref-get t k))
(defn tput! [t k v] (jolt.host/ref-put! t k v))
(defn table? [x] (jolt.host/table? x))

;; binary bytes only — these objects never carry text, so coerce through
;; byte-array (a seq/byte-array round-trips; never the UTF-8 read/write-bytes).
(defn ->ba [x]
  (cond
    (and (table? x) (#{:jolt.crypto/key :jolt.crypto/iv
                       :jolt.crypto/public-key :jolt.crypto/private-key
                       :jolt.crypto/x509-spec :jolt.crypto/pkcs8-spec}
                     (tget x :jolt/type)))
    (tget x :bytes)
    :else (byte-array x)))

(defn as-ba [x]
  ;; Native calls only read their input while the call is in progress. Avoid
  ;; rebuilding an existing byte array through its boxed sequence in that case.
  (if (bytes? x) x (->ba x)))

(defn snapshot-ba [x]
  ;; Stateful update methods must consume the caller's bytes when update is
  ;; called, not retain an array the caller can mutate before digest/sign.
  (aclone (as-ba x)))

(defn ba-window
  "A copy of the [off, off+len) window of a byte array — the JVM's
  update/digest/doFinal (bytes, off, len) overloads consume exactly this."
  [x off len]
  (let [src (as-ba x) out (byte-array len)]
    (System/arraycopy src off out 0 len)
    out))

(defn consume-update-args
  "Snapshot one update() payload: (data) is the whole array, (data off len) the
  window. Either way the caller's bytes are consumed now, not retained."
  [data more]
  (if (= 2 (count more))
    (ba-window data (first more) (second more))
    (snapshot-ba data)))

(defn concat-bas
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

(defn with-ptrs
  "Alloc a C buffer per byte-array in `bas`, copy each in, run (f ptrs…), free all."
  [bas f]
  (let [ptrs (mapv (fn [ba] (let [n (max 1 (alength ba)) p (ffi/alloc n)]
                              (ffi/write-array p ba) p))
                   bas)]
    (try (apply f ptrs) (finally (doseq [p ptrs] (ffi/free p))))))

(def ptr-size (ffi/sizeof :pointer))

(defn der-out
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

(defn pkey-type [pkey]
  (let [name-ptr (c-pkey-type-name pkey)]
    (when-not (ffi/null? name-ptr)
      (case (ffi/ptr->string name-ptr)
        "ED25519" "Ed25519"
        "ED448" "Ed448"
        (ffi/ptr->string name-ptr)))))

;; --- memory BIOs ------------------------------------------------------------
(defn with-mem-bio
  "A memory BIO over `bytes`, run (f bio), freed."
  [bytes f]
  (let [bytes (as-ba bytes) n (alength bytes) buf (ffi/alloc (max 1 n))]
    (try
      (ffi/write-array buf bytes)
      (let [bio (c-bio-new-mem-buf buf n)]
        (when (ffi/null? bio) (throw (ex-info "BIO_new_mem_buf failed" {})))
        (try (f bio) (finally (c-bio-free bio))))
      (finally (ffi/free buf)))))

(defn bio-mem-string
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
