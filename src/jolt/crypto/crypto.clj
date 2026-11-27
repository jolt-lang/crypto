;; Copyright (c) 2013-2016 Andrey Antukh <niwi@niwi.nz>
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.
;;
;; Modified in 2026 for Jolt: replaced Bouncy Castle engines with stateful
;; OpenSSL EVP contexts and added exact window validation, native cleanup, and
;; Buddy-compatible high-level authenticated encryption.

(ns jolt.crypto.crypto
  "Crypto engines low-level abstraction."
  (:require [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.mac :as mac]
            [jolt.crypto.padding :as padding]))

(defn output-size
  "Get the output size of the aead block cipher."
  [engine length]
  (.getOutputSize engine (int length)))

(def get-output-size
  "A backward compatibility alias for `output-size` function."
  output-size)

(defn block-size
  "Return the block size of the block cipher."
  [engine]
  (.getBlockSize engine))

(def get-block-size
  "A backward compatibility alias for `block-size` function."
  block-size)

(defprotocol ICipherInit
  (-init [engine params] "Initialize cipher engine.")
  (-end [engine out offset] "Finalize cipher engine."))

(defprotocol IBlockCipherLike
  (^:private -process-block [_ in inoff out outoff]))

(defprotocol IStreamCipherLike
  (^:private -process-bytes [_ in inoff inlen out outoff]))

(defn- validate-input-window [input offset length]
  (let [input-length (count input)]
    (when (or (neg? offset)
              (neg? length)
              (> offset input-length)
              (> length (- input-length offset)))
      (throw (ex-info "Invalid cipher input window"
                      {:offset offset :length length :input-length input-length})))))

(defn- validate-output-window [output offset required-length]
  (let [output-length (count output)]
    (when (or (neg? offset)
              (> offset output-length)
              (> required-length (- output-length offset)))
      (throw (ex-info "Invalid cipher output window"
                      {:output-offset offset
                       :output-length output-length
                       :required-length required-length})))))

(defn- require-context [holder]
  (or @holder
      (throw (ex-info "Cipher engine is not initialized or has been finalized" {}))))

(defn- initialize-native! [engine algorithm mode holder operation params]
  (openssl/free-cipher-context! holder)
  (try
    (let [op (or (:op params) :encrypt)
          key (codecs/to-bytes (:key params))
          iv (some-> (:iv params) codecs/to-bytes)
          ctx (openssl/cipher-context algorithm mode op key iv params)]
      (reset! holder ctx)
      (reset! operation op)
      engine)
    (catch Exception e
      (openssl/free-cipher-context! holder)
      (throw e))))

(defn- process-native! [holder operation input inoff inlen out outoff]
  (validate-input-window input inoff inlen)
  (validate-output-window out outoff inlen)
  (let [ctx (require-context holder)]
    (try
      (let [window (bytes/slice input inoff (+ inoff inlen))
            result (openssl/cipher-update ctx @operation window)]
        (System/arraycopy result 0 out outoff inlen)
        inlen)
      (catch Exception e
        (openssl/free-cipher-context! holder)
        (throw e)))))

(defn- finalize-native! [holder operation output offset]
  (try
    (when-let [ctx @holder]
      (validate-output-window output offset 0)
      (openssl/cipher-final ctx @operation))
    0
    (finally
      (openssl/free-cipher-context! holder))))

(defrecord OpenSSLBlockCipher [algorithm mode context operation]
  ICipherInit
  (-init [this params]
    (initialize-native! this algorithm mode context operation params))
  (-end [_ out offset]
    (finalize-native! context operation out offset))

  IBlockCipherLike
  (-process-block [_ in inoff out outoff]
    (process-native! context operation in inoff 16 out outoff))

  Object
  (getBlockSize [_] 16))

(defn- gcm-encrypt-window! [ctx window out outoff]
  (let [length (count window)]
    (validate-output-window out outoff length)
    (System/arraycopy (openssl/cipher-update ctx :encrypt window) 0 out outoff length)
    length))

(defn- gcm-decrypt-window!
  "Decrypt what the window adds, holding back the last 16 bytes seen so far in
  pending: until the input ends they may be the authentication tag."
  [ctx pending window out outoff]
  (let [combined (bytes/concat @pending window)
        total (count combined)
        output-length (max 0 (- total 16))]
    (validate-output-window out outoff output-length)
    (reset! pending (bytes/slice combined output-length total))
    (when (pos? output-length)
      (let [result (openssl/cipher-update ctx :decrypt
                                          (bytes/slice combined 0 output-length))]
        (System/arraycopy result 0 out outoff output-length)))
    output-length))

(defn- process-gcm! [{:keys [context operation pending]} input inoff inlen out outoff]
  (validate-input-window input inoff inlen)
  (let [ctx (require-context context)]
    (try
      (let [window (bytes/slice input inoff (+ inoff inlen))]
        (if (= :encrypt @operation)
          (gcm-encrypt-window! ctx window out outoff)
          (gcm-decrypt-window! ctx pending window out outoff)))
      (catch Exception e
        (reset! pending (byte-array 0))
        (openssl/free-cipher-context! context)
        (throw e)))))

(defn- finalize-gcm! [holder operation pending output offset]
  (try
    (if-let [ctx @holder]
      (let [op @operation
            encrypt? (= :encrypt op)]
        (validate-output-window output offset (if encrypt? 16 0))
        (let [result (try
                       (openssl/gcm-final ctx op (when-not encrypt? @pending))
                       (catch Exception e
                         (throw (ex-info
                                 (str (if encrypt?
                                        "Couldn't generate gcm authentication tag: "
                                        "Couldn't validate gcm authentication tag: ")
                                      (.getMessage e))
                                 {:type (if encrypt? :encryption :validation)
                                  :cause :authtag}))))]
          (if encrypt?
            (do
              (System/arraycopy result 0 output offset 16)
              16)
            0)))
      0)
    (finally
      (reset! pending (byte-array 0))
      (openssl/free-cipher-context! holder))))

(defrecord OpenSSLGCMBlockCipher [algorithm context operation pending]
  ICipherInit
  (-init [this params]
    (try
      (when-not (= 128 (:tagsize params 128))
        (throw (ex-info "AES-GCM requires a 128-bit authentication tag"
                        {:tagsize (:tagsize params)})))
      (reset! pending (byte-array 0))
      (initialize-native! this algorithm :gcm context operation params)
      (catch Exception e
        (reset! pending (byte-array 0))
        (openssl/free-cipher-context! context)
        (throw e))))
  (-end [_ out offset]
    (finalize-gcm! context operation pending out offset))

  IBlockCipherLike
  (-process-block [this in inoff out outoff]
    (process-gcm! this in inoff (- (count in) inoff) out outoff))

  IStreamCipherLike
  (-process-bytes [this in inoff inlen out outoff]
    (process-gcm! this in inoff inlen out outoff))

  Object
  (getBlockSize [_] 16)
  (getOutputSize [_ length]
    (if (= :decrypt @operation)
      (max 0 (- length 16))
      (+ length 16))))

(defrecord OpenSSLStreamCipher [algorithm context operation]
  ICipherInit
  (-init [this params]
    (initialize-native! this algorithm :chacha context operation params))
  (-end [_ out offset]
    (finalize-native! context operation out offset))

  IBlockCipherLike
  (-process-block [_ in inoff out outoff]
    (process-native! context operation in inoff (- (count in) inoff) out outoff))

  IStreamCipherLike
  (-process-bytes [_ in inoff inlen out outoff]
    (process-native! context operation in inoff inlen out outoff))

  Object
  (getBlockSize [_] 1))

(defn init!
  "Initialize the cipher engine."
  [engine params]
  (-init engine params))

(def initialize!
  "A backward compatibility alias for `init!`"
  init!)

(defn process-block!
  "Encrypt or decrypt bytes using the specified engine."
  ([engine in]
   (let [out (byte-array (block-size engine))]
     (-process-block engine in 0 out 0)
     out))
  ([engine in inoff out outoff]
   (-process-block engine in inoff out outoff)))

(defn process-bytes!
  "Encrypt or decrypt bytes using a stream or AEAD cipher."
  ([engine in]
   (let [length (alength in)
         out (byte-array length)]
     (-process-bytes engine in 0 length out 0)
     out))
  ([engine in inoff out outoff]
   (-process-bytes engine in inoff (- (alength in) inoff) out outoff))
  ([engine in inoff inlen out outoff]
   (-process-bytes engine in inoff inlen out outoff)))

(defn end!
  "Finalize the encryption process. Non-AEAD engines emit no bytes and return 0."
  [engine output offset]
  (-end engine output offset))

(def ^:no-doc +block-cipher-engines+
  {:aes #(->OpenSSLBlockCipher :aes nil (atom nil) (atom nil))})

(def ^:no-doc +stream-cipher-engines+
  {:chacha #(->OpenSSLStreamCipher :chacha (atom nil) (atom nil))})

(def ^:no-doc +cipher-modes+
  {:ecb #(assoc % :mode :ecb)
   :cbc #(assoc % :mode :cbc)
   :gcm #(->OpenSSLGCMBlockCipher (:algorithm %) (atom nil) (atom nil)
                                  (atom (byte-array 0)))
   :ctr #(assoc % :mode :ctr)
   :sic #(assoc % :mode :sic)
   :ofb #(assoc % :mode :ofb)})

(defn block-cipher
  "Block cipher engine constructor."
  [alg mode]
  (if-let [modefactory (get +cipher-modes+ mode)]
    (if-let [enginefactory (get +block-cipher-engines+ alg)]
      (modefactory (enginefactory))
      (throw (ex-info "Cipher algorighm not supported." {:alg alg})))
    (throw (ex-info "Cipher mode not supported." {:mode mode}))))

(defn stream-cipher
  "Stream cipher engine constructor."
  [alg]
  (if-let [enginefactory (get +stream-cipher-engines+ alg)]
    (enginefactory)
    (throw (ex-info "Cipher algorighm not supported." {:alg alg}))))

(defn split-by-blocksize
  "Split a byte array into blocks, zero-padding the final partial block."
  ([input blocksize]
   (split-by-blocksize input blocksize false))
  ([input blocksize additional]
   (let [input-size (count input)]
     (loop [offset 0
            result (transient [])]
       (let [remaining (- input-size offset)]
         (cond
           (zero? remaining)
           (persistent!
            (if additional
              (conj! result (byte-array blocksize))
              result))

           (< remaining blocksize)
           (let [buffer (byte-array blocksize)]
             (System/arraycopy input offset buffer 0 remaining)
             (persistent! (conj! result buffer)))

           :else
           (let [buffer (byte-array blocksize)]
             (System/arraycopy input offset buffer 0 blocksize)
             (recur (+ offset blocksize) (conj! result buffer)))))))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High-Level Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05

(defn encrypt-cbc
  "Encrypt arbitrary length input using CBC with PKCS7 padding."
  {:internal true :no-doc true}
  [cipher input key iv]
  (let [blocksize (get-block-size cipher)
        blocks (split-by-blocksize input blocksize true)
        inputsize (count input)]
    (initialize! cipher {:op :encrypt :iv iv :key key})
    (try
      (apply bytes/concat
             (loop [blocks blocks
                    processed (transient [])
                    pos 0]
               (let [block (first blocks)
                     last? (empty? (rest blocks))]
                 (if-not last?
                   (recur (rest blocks)
                          (conj! processed (process-block! cipher block))
                          (+ pos (count block)))
                   (let [remaining (- inputsize pos)]
                     (padding/pad! block remaining :pkcs7)
                     (persistent!
                      (conj! processed (process-block! cipher block))))))))
      (finally
        (end! cipher (byte-array 0) 0)))))

(defn decrypt-cbc
  "Decrypt arbitrary length input using CBC with PKCS7 padding."
  {:internal true :no-doc true}
  [cipher input key iv]
  (let [blocksize (get-block-size cipher)
        blocks (split-by-blocksize input blocksize false)]
    (initialize! cipher {:op :decrypt :iv iv :key key})
    (try
      (apply bytes/concat
             (loop [blocks blocks
                    processed (transient [])]
               (let [block (process-block! cipher (first blocks))
                     last? (empty? (rest blocks))]
                 (if-not last?
                   (recur (rest blocks)
                          (conj! processed block))
                   (let [result (padding/unpad block :pkcs7)]
                     (persistent!
                      (conj! processed result)))))))
      (finally
        (end! cipher (byte-array 0) 0)))))

(defn encrypt-gcm
  "Encrypt arbitrary length input and append a 128-bit GCM authentication tag."
  {:internal true :no-doc true}
  [cipher input key iv aad]
  (try
    (-init cipher {:iv iv :key key :tagsize 128 :op :encrypt :aad aad})
    (let [outputlength (get-output-size cipher (count input))
          output (byte-array outputlength)
          offset (process-bytes! cipher input 0 output 0)]
      (end! cipher output offset)
      output)
    (finally
      (openssl/free-cipher-context! (:context cipher)))))

(defn decrypt-gcm
  "Verify and decrypt input carrying a trailing 128-bit GCM authentication tag."
  {:internal true :no-doc true}
  [cipher ciphertext key iv aad]
  (try
    (when (< (count ciphertext) 16)
      (throw (ex-info "Couldn't validate gcm authentication tag: truncated input"
                      {:type :validation :cause :authtag})))
    (-init cipher {:iv iv :key key :tagsize 128 :op :decrypt :aad aad})
    (let [input (bytes/copy ciphertext)
          outputlength (get-output-size cipher (count input))
          output (byte-array outputlength)
          offset (process-bytes! cipher input 0 output 0)]
      (end! cipher output offset)
      output)
    (finally
      (openssl/free-cipher-context! (:context cipher)))))

(defn- aad->bytes [aad]
  (let [length (* (count aad) 8)
        buffer (java.nio.ByteBuffer/allocate 8)]
    (.putLong buffer length)
    (.array buffer)))

(def ^:private authenticated-algorithms
  {:aes128-cbc-hmac-sha256 {:mode :cbc :key-length 32 :iv-length 16
                            :digest :sha256 :tag-length 16}
   :aes192-cbc-hmac-sha384 {:mode :cbc :key-length 48 :iv-length 16
                            :digest :sha384 :tag-length 24}
   :aes256-cbc-hmac-sha512 {:mode :cbc :key-length 64 :iv-length 16
                            :digest :sha512 :tag-length 32}
   :aes128-gcm {:mode :gcm :key-length 16 :iv-length 12 :tag-length 16}
   :aes192-gcm {:mode :gcm :key-length 24 :iv-length 12 :tag-length 16}
   :aes256-gcm {:mode :gcm :key-length 32 :iv-length 12 :tag-length 16}})

(defn- algorithm-config [alg key iv]
  (let [{:keys [key-length iv-length] :as config}
        (or (get authenticated-algorithms alg)
            (throw (ex-info (str "Unsupported authenticated encryption algorithm: " alg)
                            {:alg alg})))]
    (when-not (= key-length (count key))
      (throw (ex-info "Wrong key length for authenticated encryption"
                      {:alg alg :key-length (count key) :expected key-length})))
    (when-not (= iv-length (count iv))
      (throw (ex-info "Wrong IV length for authenticated encryption"
                      {:alg alg :iv-length (count iv) :expected iv-length})))
    config))

(defn- generate-authtag [{:keys [digest input authkey iv aad]}]
  (let [al (if aad (aad->bytes aad) (byte-array 0))
        data (bytes/concat (or aad (byte-array 0)) iv input al)
        fulltag (mac/hash data {:key authkey :alg :hmac :digest digest})
        truncatesize (quot (count fulltag) 2)]
    (bytes/slice fulltag 0 truncatesize)))

(defn- encrypt-cbc-hmac [config input key iv aad]
  (let [keysize (quot (:key-length config) 2)
        authkey (bytes/slice key 0 keysize)
        encryptionkey (bytes/slice key keysize (* 2 keysize))
        ciphertext (encrypt-cbc (block-cipher :aes :cbc) input encryptionkey iv)
        tag (generate-authtag {:digest (:digest config)
                               :input ciphertext
                               :authkey authkey
                               :iv iv
                               :aad aad})]
    (bytes/concat ciphertext tag)))

(defn- invalid-cbc-hmac-message []
  (ex-info "Message seems corrupt or manipulated."
           {:type :validation :cause :authtag}))

(defn- decrypt-cbc-hmac [config input key iv aad]
  (let [taglen (:tag-length config)
        inputlen (count input)
        ciphertext-length (- inputlen taglen)]
    (when (or (neg? ciphertext-length)
              (zero? ciphertext-length)
              (not (zero? (mod ciphertext-length 16))))
      (throw (invalid-cbc-hmac-message)))
    (let [keysize (quot (:key-length config) 2)
          authkey (bytes/slice key 0 keysize)
          encryptionkey (bytes/slice key keysize (* 2 keysize))
          ciphertext (bytes/slice input 0 ciphertext-length)
          authtag (bytes/slice input ciphertext-length inputlen)
          expected (generate-authtag {:digest (:digest config)
                                      :input ciphertext
                                      :authkey authkey
                                      :iv iv
                                      :aad aad})]
      (when-not (bytes/equals? authtag expected)
        (throw (invalid-cbc-hmac-message)))
      (decrypt-cbc (block-cipher :aes :cbc) ciphertext encryptionkey iv))))

(defn- encrypt-with-algorithm [alg input key iv aad]
  (let [config (algorithm-config alg key iv)]
    (case (:mode config)
      :cbc (encrypt-cbc-hmac config input key iv aad)
      :gcm (encrypt-gcm (block-cipher :aes :gcm) input key iv aad))))

(defn- decrypt-with-algorithm [alg input key iv aad]
  (let [config (algorithm-config alg key iv)]
    (case (:mode config)
      :cbc (decrypt-cbc-hmac config input key iv aad)
      :gcm (decrypt-gcm (block-cipher :aes :gcm) input key iv aad))))

(defn encrypt
  "Encrypt arbitrary length data using a Buddy authenticated-encryption scheme.
  The default scheme is `:aes128-cbc-hmac-sha256`."
  ([input key iv]
   (encrypt input key iv nil))
  ([input key iv {:keys [algorithm alg aad]
                  :or {alg :aes128-cbc-hmac-sha256}}]
   (encrypt-with-algorithm (or algorithm alg) input
                           (codecs/to-bytes key) (codecs/to-bytes iv) aad)))

(defn decrypt
  "Authenticate and decrypt data produced by `encrypt`."
  ([input key iv]
   (decrypt input key iv {}))
  ([input key iv {:keys [algorithm alg aad]
                  :or {alg :aes128-cbc-hmac-sha256}}]
   (decrypt-with-algorithm (or algorithm alg) input
                           (codecs/to-bytes key) (codecs/to-bytes iv) aad)))
