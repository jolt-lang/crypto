;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle engines with snapshotting
;; OpenSSL-backed records and limited the API to default-provider algorithms.

(ns jolt.crypto.hash
  "Basic crypto primitives that used for more high
  level abstractions."
  (:refer-clojure :exclude [update reset!])
  (:require [clojure.java.io :as io]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.internal.openssl :as openssl])
  (:import java.io.InputStream))

(defprotocol IDigest
  (-digest [input engine] "Low level interface, always returns bytes"))

(defprotocol IEngine
  "Hash engine common interface definition."
  (-reset [_] "Reset the hash engine to its initial state.")
  (-update [_ input offset length] "Update bytes in a current instance.")
  (-end [_] "Return the computed mac and reset the engine."))

(defrecord OpenSSLDigestEngine [algorithm chunks]
  IEngine
  (-reset [_]
    (clojure.core/reset! chunks [])
    nil)
  (-update [_ input offset length]
    (let [input-length (count input)]
      (when (or (neg? offset)
                (neg? length)
                (> offset input-length)
                (> length (- input-length offset)))
        (throw (ex-info "Invalid digest update window"
                        {:offset offset :length length :input-length input-length})))
      (let [window (bytes/slice input offset (+ offset length))]
        (swap! chunks conj window)
        nil)))
  (-end [this]
    (try
      (openssl/digest-bytes algorithm (apply bytes/concat @chunks))
      (finally
        (-reset this)))))

(defn- make-engine [algorithm]
  (->OpenSSLDigestEngine algorithm (atom [])))

(def ^:no-doc +digest-engines+
  {:sha256 #(make-engine :sha256)
   :sha384 #(make-engine :sha384)
   :sha512 #(make-engine :sha512)
   :sha1 #(make-engine :sha1)
   :ripemd160 #(make-engine :ripemd160)
   :md5 #(make-engine :md5)
   :sha3-256 #(make-engine :sha3-256)
   :sha3-384 #(make-engine :sha3-384)
   :sha3-512 #(make-engine :sha3-512)
   :blake2b-512 #(make-engine :blake2b-512)})

(defn reset!
  [engine]
  (-reset engine))

(defn update!
  ([engine input]
   (-update engine input 0 (count input)))
  ([engine input offset]
   (-update engine input offset (- (count input) offset)))
  ([engine input offset length]
   (-update engine input offset length)))

(defn end!
  [engine]
  (-end engine))

(defn resolve-digest-engine
  "Helper function for make Digest instances
  from algorithm parameter."
  [engine]
  (cond
    (keyword? engine)
    (when-let [factory (get +digest-engines+ engine)]
      (factory))
    (satisfies? IEngine engine) engine
    (fn? engine) (engine)))

(defn- hash-plain-data [input engine]
  (-reset engine)
  (-update engine input 0 (count input))
  (-end engine))

(defn- hash-stream-data [input engine]
  (-reset engine)
  (let [buffer (byte-array 5120)]
    (loop []
      (let [readed (.read input buffer 0 5120)]
        (when-not (= readed -1)
          (-update engine buffer 0 readed)
          (recur))))
    (-end engine)))

(extend-protocol IDigest
  String
  (-digest [input engine]
    (hash-plain-data (codecs/str->bytes input) engine))

  InputStream
  (-digest [input engine]
    (hash-stream-data input engine))

  java.io.File
  (-digest [input engine]
    (with-open [stream (io/input-stream input)]
      (hash-stream-data stream engine)))

  Object
  (-digest [input engine]
    (cond
      (bytes/bytes? input)
      (hash-plain-data input engine)

      (instance? java.net.URL input)
      (with-open [stream (io/input-stream input)]
        (hash-stream-data stream engine))

      (instance? java.net.URI input)
      (with-open [stream (io/input-stream input)]
        (hash-stream-data stream engine))

      :else
      (throw (IllegalArgumentException.
              (str "Unsupported digest input: " (class input)))))))

(defn digest
  "Generic function for create cryptographic hash."
  [input alg-or-engine]
  (let [engine (resolve-digest-engine alg-or-engine)]
    (when-not engine
      (throw (ex-info (str "Unsupported digest algorithm: " alg-or-engine)
                      {:algorithm alg-or-engine})))
    (-digest input engine)))

(defn blake2b
  "BLAKE2 is a cryptographic hash function faster than MD5,
  SHA-1, SHA-2, and SHA-3, yet is at least as secure as the
  latest standard SHA-3."
  [input length]
  (when-not (= 64 length)
    (throw (ex-info "Only 64-byte BLAKE2b-512 output is supported"
                    {:algorithm :blake2b-512 :length length})))
  (digest input :blake2b-512))

(defn blake2b-512
  "BLAKE2 cryptographic hash function with fixed output
  digest size to 512 bits."
  [input]
  (digest input :blake2b-512))

(defn sha256 [input]
  (digest input :sha256))

(defn sha384 [input]
  (digest input :sha384))

(defn sha512 [input]
  (digest input :sha512))

(defn sha3-256 [input]
  (digest input :sha3-256))

(defn sha3-384 [input]
  (digest input :sha3-384))

(defn sha3-512 [input]
  (digest input :sha3-512))

(defn sha1 [input]
  (digest input :sha1))

(defn md5 [input]
  (digest input :md5))

(defn ripemd160 [input]
  (digest input :ripemd160))
