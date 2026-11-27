(ns jolt.crypto.internal.pkcs8
  "pbeWithMD5AndDES-CBC encrypted PKCS#8, which OpenSSL 3's generic decoder
  rejects even though DES-CBC remains available through exported low-level
  functions. jolt.crypto falls back to this for an ENCRYPTED PRIVATE KEY that
  OpenSSL refuses, without loading the legacy provider."
  (:require [clojure.string :as str]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.internal.support :refer [ba-window concat-bas with-ptrs]]
            [jolt.ffi :as ffi]))

(ffi/defcfn c-des-set-key-unchecked "DES_set_key_unchecked" [:pointer :pointer] :void)
(ffi/defcfn c-des-cbc-encrypt "DES_cbc_encrypt" [:pointer :pointer :long :pointer :pointer :int] :void)

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
         value (openssl/digest-bytes :md5 (concat-bas [password salt]))]
    (if (= iteration iterations)
      value
      (recur (inc iteration) (openssl/digest-bytes :md5 value)))))

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

(defn decrypt-md5-des
  "The PKCS#8 PrivateKeyInfo DER inside a pbeWithMD5AndDES-CBC ENCRYPTED
  PRIVATE KEY PEM. Throws ex-info, with ::not-md5-des in its data when the key
  uses some other scheme."
  [text passphrase]
  (let [{:keys [salt iterations ciphertext]} (encrypted-pkcs8-fields text)
        password (.getBytes passphrase "UTF-8")
        derived (pbkdf1-md5 password salt iterations)
        key (ba-window derived 0 8)
        iv (ba-window derived 8 8)]
    (remove-pkcs7-padding (des-cbc-decrypt key iv ciphertext))))
