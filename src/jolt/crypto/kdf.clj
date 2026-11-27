;; Copyright 2013-2016 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle generators with the
;; standards-compatible constructions over the public digest/HMAC interfaces
;; and OpenSSL's native PBKDF2-HMAC operation.

(ns jolt.crypto.kdf
  "Key derivation function interface."
  (:require [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.hash :as hash]
            [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.mac :as mac])
  (:import java.nio.ByteBuffer))

(def ^:const +pbkdf2-iterations+ 1000)

(defprotocol IKDF
  (-get-bytes [_ length] "Get the next N bytes from kdf."))

(defmulti engine
  "Key derivation function engine constructor."
  :alg)

(defn get-bytes
  [engine length]
  (-get-bytes engine length))

(defn get-buffer
  [engine length]
  (ByteBuffer/wrap (-get-bytes engine length)))

(defn- validate-length! [length]
  (when-not (and (integer? length) (<= 0 length 2147483647))
    (throw (ex-info "KDF output length must be a non-negative 32-bit integer"
                    {:length length})))
  length)

(defrecord FunctionalKDF [derive]
  IKDF
  (-get-bytes [_ length]
    (validate-length! length)
    (if (zero? length)
      (byte-array 0)
      (derive length))))

(defn- option-bytes [value]
  (bytes/copy (codecs/to-bytes value)))

(defn- digest-info [digest]
  (let [resolved (hash/resolve-digest-engine digest)
        algorithm (:algorithm resolved)]
    (when-not algorithm
      (throw (ex-info (str "Unsupported digest algorithm: " digest)
                      {:algorithm digest})))
    {:algorithm algorithm
     :length (openssl/digest-length algorithm)}))

(defn- hmac [algorithm key data]
  (mac/hash data {:key key :alg :hmac :digest algorithm}))

(defn- counter-bytes [value r]
  (let [width (/ r 8)
        output (byte-array width)]
    (dotimes [index width]
      (let [shift (* 8 (- width 1 index))]
        (aset-byte output index
                   (unchecked-byte (bit-and (bit-shift-right value shift) 0xff)))))
    output))

(defn- validate-counter-width! [r]
  (when-not (#{8 16 24 32} r)
    (throw (ex-info "Length of counter should be 8, 16, 24 or 32" {:r r})))
  r)

(defn- counter-limit [r]
  (dec (bit-shift-left 1 r)))

(defn- streaming-derive
  ([next-block]
   (streaming-derive next-block nil))
  ([next-block maximum-counter]
   (let [counter (atom 1)
         current (atom nil)
         offset (atom 0)]
     (fn [length]
       (let [output (byte-array length)]
         (loop [written 0]
           (if (= written length)
             output
             (do
               (when (or (nil? @current) (= @offset (count @current)))
                 (when (and maximum-counter (> @counter maximum-counter))
                   (throw (ex-info "KDF counter exceeds the construction limit"
                                   {:counter @counter :maximum-counter maximum-counter})))
                 (reset! current (next-block @counter))
                 (swap! counter inc)
                 (reset! offset 0))
               (let [amount (min (- length written) (- (count @current) @offset))]
                 (System/arraycopy @current @offset output written amount)
                 (swap! offset + amount)
                 (recur (+ written amount)))))))))))

(defn- limited-derive [derive maximum]
  (let [generated (atom 0)]
    (fn [length]
      (when (> (+ @generated length) maximum)
        (throw (ex-info "KDF output exceeds the construction limit"
                        {:length length :generated @generated :maximum maximum})))
      (let [output (derive length)]
        (swap! generated + length)
        output))))

(defmethod engine :hkdf
  [{:keys [key salt info digest]}]
  (let [{:keys [algorithm length]} (digest-info digest)
        key (option-bytes key)
        salt (option-bytes salt)
        info (option-bytes info)
        prk (hmac algorithm salt key)
        previous (atom (byte-array 0))
        derive (streaming-derive
                (fn [counter]
                  (let [block (hmac algorithm prk
                                    (bytes/concat @previous info
                                                  (byte-array [(unchecked-byte counter)])))]
                    (reset! previous block)
                    block))
                255)]
    (->FunctionalKDF (limited-derive derive (* 255 length)))))

(defmethod engine :hkdf+sha256
  [options]
  (engine (assoc options :alg :hkdf :digest :sha256)))

(defmethod engine :hkdf+sha386
  [options]
  (engine (assoc options :alg :hkdf :digest :sha386)))

(defmethod engine :hkdf+sha512
  [options]
  (engine (assoc options :alg :hkdf :digest :sha512)))

(defmethod engine :hkdf+blake2b-512
  [options]
  (engine (assoc options :alg :hkdf :digest :blake2b-512)))

(defn- digest-kdf-engine [{:keys [key salt digest]} initial-counter]
  (let [{:keys [algorithm]} (digest-info digest)
        key (option-bytes key)
        salt (option-bytes salt)]
    (->FunctionalKDF
     (fn [length]
       (loop [counter initial-counter
              blocks []]
        (let [output-length (reduce + 0 (map count blocks))]
          (if (>= output-length length)
            (bytes/slice (apply bytes/concat blocks) 0 length)
            (let [block (hash/digest (bytes/concat key (counter-bytes counter 32) salt)
                                     algorithm)]
              (recur (inc counter) (conj blocks block))))))))))

(defmethod engine :kdf1
  [options]
  (digest-kdf-engine options 0))

(defmethod engine :kdf1+sha256
  [options]
  (engine (assoc options :alg :kdf1 :digest :sha256)))

(defmethod engine :kdf1+sha386
  [options]
  (engine (assoc options :alg :kdf1 :digest :sha386)))

(defmethod engine :kdf1+sha512
  [options]
  (engine (assoc options :alg :kdf1 :digest :sha512)))

(defmethod engine :kdf1+blake2b-512
  [options]
  (engine (assoc options :alg :kdf1 :digest :blake2b-512)))

(defmethod engine :kdf2
  [options]
  (digest-kdf-engine options 1))

(defmethod engine :kdf2+sha256
  [options]
  (engine (assoc options :alg :kdf2 :digest :sha256)))

(defmethod engine :kdf2+sha386
  [options]
  (engine (assoc options :alg :kdf2 :digest :sha386)))

(defmethod engine :kdf2+sha512
  [options]
  (engine (assoc options :alg :kdf2 :digest :sha512)))

(defmethod engine :kdf2+blake2b-512
  [options]
  (engine (assoc options :alg :kdf2 :digest :blake2b-512)))

(defmethod engine :cmkdf
  [{:keys [key salt digest r] :or {r 32}}]
  (validate-counter-width! r)
  (let [{:keys [algorithm length]} (digest-info digest)
        key (option-bytes key)
        salt (option-bytes salt)
        maximum-counter (counter-limit r)
        derive (streaming-derive
                (fn [counter]
                  (hmac algorithm key (bytes/concat (counter-bytes counter r) salt)))
                maximum-counter)]
    (->FunctionalKDF
     (limited-derive derive (* maximum-counter length)))))

(defmethod engine :cmkdf+sha256
  [options]
  (engine (assoc options :alg :cmkdf :digest :sha256)))

(defmethod engine :cmkdf+sha386
  [options]
  (engine (assoc options :alg :cmkdf :digest :sha386)))

(defmethod engine :cmkdf+sha512
  [options]
  (engine (assoc options :alg :cmkdf :digest :sha512)))

(defmethod engine :cmkdf+blake2b-512
  [options]
  (engine (assoc options :alg :cmkdf :digest :blake2b-512)))

(defmethod engine :fmkdf
  [{:keys [key salt digest r counter] :or {r 32 counter true}}]
  (when counter
    (validate-counter-width! r))
  (let [{:keys [algorithm length]} (digest-info digest)
        key (option-bytes key)
        previous (atom (option-bytes salt))
        maximum-counter (when counter (counter-limit r))
        derive (streaming-derive
                (fn [iteration]
                  (let [input (if counter
                                (bytes/concat @previous (counter-bytes iteration r))
                                @previous)
                        block (hmac algorithm key input)]
                    (reset! previous block)
                    block))
                maximum-counter)]
    (->FunctionalKDF
     (if maximum-counter
       (limited-derive derive (* maximum-counter length))
       derive))))

(defmethod engine :fmkdf+sha256
  [options]
  (engine (assoc options :alg :fmkdf :digest :sha256)))

(defmethod engine :fmkdf+sha386
  [options]
  (engine (assoc options :alg :fmkdf :digest :sha386)))

(defmethod engine :fmkdf+sha512
  [options]
  (engine (assoc options :alg :fmkdf :digest :sha512)))

(defmethod engine :fmkdf+blake2b-512
  [options]
  (engine (assoc options :alg :fmkdf :digest :blake2b-512)))

(defmethod engine :dpimkdf
  [{:keys [key salt digest r counter] :or {r 32 counter true}}]
  (when counter
    (validate-counter-width! r))
  (let [{:keys [algorithm length]} (digest-info digest)
        key (option-bytes key)
        salt (option-bytes salt)
        a-value (atom salt)
        maximum-counter (when counter (counter-limit r))
        derive (streaming-derive
                (fn [iteration]
                  (let [a (hmac algorithm key @a-value)]
                    (reset! a-value a)
                    (hmac algorithm key
                          (if counter
                            (bytes/concat a (counter-bytes iteration r) salt)
                            (bytes/concat a salt)))))
                maximum-counter)]
    (->FunctionalKDF
     (if maximum-counter
       (limited-derive derive (* maximum-counter length))
       derive))))

(defmethod engine :dpimkdf+sha256
  [options]
  (engine (assoc options :alg :dpimkdf :digest :sha256)))

(defmethod engine :dpimkdf+sha386
  [options]
  (engine (assoc options :alg :dpimkdf :digest :sha386)))

(defmethod engine :dpimkdf+sha512
  [options]
  (engine (assoc options :alg :dpimkdf :digest :sha512)))

(defmethod engine :dpimkdf+blake2b-512
  [options]
  (engine (assoc options :alg :dpimkdf :digest :blake2b-512)))

(defmethod engine :pbkdf2
  [{:keys [key salt digest iterations]}]
  (let [{:keys [algorithm]} (digest-info digest)
        key (option-bytes key)
        salt (option-bytes salt)
        iterations (or iterations +pbkdf2-iterations+)]
    (->FunctionalKDF
     (fn [length]
       (openssl/pbkdf2-bytes algorithm key salt iterations length)))))

(defmethod engine :pbkdf2+sha256
  [options]
  (engine (assoc options :alg :pbkdf2 :digest :sha256)))

(defmethod engine :pbkdf2+sha384
  [options]
  (engine (assoc options :alg :pbkdf2 :digest :sha384)))

(defmethod engine :pbkdf2+sha512
  [options]
  (engine (assoc options :alg :pbkdf2 :digest :sha512)))
