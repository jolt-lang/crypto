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
;; OpenSSL EVP contexts and added exact window validation and native cleanup.

(ns jolt.crypto.crypto
  "Crypto engines low-level abstraction."
  (:require [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.internal.openssl :as openssl]))

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
          iv (when (contains? params :iv)
               (codecs/to-bytes (:iv params)))
          ctx (openssl/cipher-context algorithm mode op key iv)]
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
