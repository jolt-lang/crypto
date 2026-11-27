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
;; Modified in 2026 for Jolt: replaced Bouncy Castle with snapshotting OpenSSL
;; HMAC and AES-Poly1305 engines and limited cipher selection to AES.

(ns jolt.crypto.mac
  "Message Authentication Code algorithms."
  (:refer-clojure :exclude [hash reset!])
  (:require [clojure.java.io :as io]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.hash :as hash]
            [jolt.crypto.internal.openssl :as openssl])
  (:import java.io.InputStream))

(defprotocol IMac
  (-hash [_ engine] "Generate the auth message code")
  (-verify [_ sig engine] "Verify the auth message code"))

(defprotocol IEngineInit
  (-init [_ options] "Initialize the mac"))

(defprotocol IEngine
  (-reset [_] "Reset engine state")
  (-update [_ input offset length] "Update the engine state.")
  (-end [_] "Generates the mac"))

(defmulti ^:no-doc engine
  "A engine constructor."
  :alg)

(defrecord OpenSSLCipherEngine [algorithm])

(def ^:no-doc +cipher-engines+
  {:aes #(->OpenSSLCipherEngine :aes)})

(defn resolve-cipher-engine
  "Given dynamic type engine, try resolve it to
  valid engine instance. By default accepts keywords
  and functions."
  [engine]
  (cond
    (keyword? engine)
    (when-let [factory (get +cipher-engines+ engine)]
      (factory))
    (instance? OpenSSLCipherEngine engine) engine
    (fn? engine) (engine)))

(defn- update-chunks [chunks input offset length]
  (let [input-length (count input)]
    (when (or (neg? offset)
              (neg? length)
              (> offset input-length)
              (> length (- input-length offset)))
      (throw (ex-info "Invalid MAC update window"
                      {:offset offset :length length :input-length input-length})))
    (swap! chunks conj (bytes/slice input offset (+ offset length)))
    nil))

(defn- reset-chunks [chunks]
  (clojure.core/reset! chunks [])
  nil)

;; ctx holds a native incremental HMAC context once the first update arrives,
;; so a stream is MACed in constant memory. end!, reset! and init! free it.
(defn- free-hmac! [ctx]
  (when-let [c @ctx]
    (clojure.core/reset! ctx nil)
    (openssl/free-hmac-context! c))
  nil)

(defrecord OpenSSLHmacEngine [algorithm key ctx]
  IEngineInit
  (-init [_ options]
    (free-hmac! ctx)
    (clojure.core/reset! key (bytes/copy (codecs/to-bytes (:key options))))
    nil)

  IEngine
  (-reset [_]
    (free-hmac! ctx))
  (-update [_ input offset length]
    (let [input-length (count input)]
      (when (or (neg? offset)
                (neg? length)
                (> offset input-length)
                (> length (- input-length offset)))
        (throw (ex-info "Invalid MAC update window"
                        {:offset offset :length length :input-length input-length}))))
    (let [c (or @ctx (clojure.core/reset! ctx (openssl/hmac-context algorithm @key)))]
      (openssl/hmac-update! c algorithm (bytes/slice input offset (+ offset length)))
      nil))
  (-end [_]
    (let [c (or @ctx (openssl/hmac-context algorithm @key))]
      (clojure.core/reset! ctx nil)
      (openssl/hmac-finish! c algorithm))))

(defrecord OpenSSLPoly1305Engine [cipher key iv chunks]
  IEngineInit
  (-init [_ options]
    (let [key-bytes (codecs/to-bytes (:key options))
          iv-bytes (codecs/to-bytes (:iv options))]
      (when-not (= 32 (count key-bytes))
        (throw (ex-info "Wrong key length (should be 32 bytes)"
                        {:key-length (count key-bytes)})))
      (when-not (= 16 (count iv-bytes))
        (throw (ex-info "Wrong iv length (should be 16 bytes)"
                        {:iv-length (count iv-bytes)})))
      (clojure.core/reset! key (bytes/copy key-bytes))
      (clojure.core/reset! iv (bytes/copy iv-bytes))
      (reset-chunks chunks)))

  IEngine
  (-reset [_]
    (reset-chunks chunks))
  (-update [_ input offset length]
    (update-chunks chunks input offset length))
  (-end [this]
    (try
      (openssl/poly1305-aes-bytes @key @iv (apply bytes/concat @chunks))
      (finally
        (-reset this)))))

(defn- digest-algorithm [digest]
  (let [resolved (hash/resolve-digest-engine digest)
        algorithm (:algorithm resolved)]
    (when-not algorithm
      (throw (ex-info (str "Invalid digest engine: " digest)
                      {:digest digest})))
    (openssl/digest-length algorithm)
    algorithm))

(defn- hmac-engine [digest]
  (->OpenSSLHmacEngine (digest-algorithm digest) (atom nil) (atom nil)))

(defn- poly1305-engine [cipher]
  (when-not (= :aes (:algorithm cipher))
    (throw (ex-info (str "Unsupported Poly1305 cipher: " (or (:algorithm cipher) cipher))
                    {:cipher (or (:algorithm cipher) cipher)})))
  (->OpenSSLPoly1305Engine cipher (atom nil) (atom nil) (atom [])))

(defmethod engine :hmac
  [options]
  (hmac-engine (:digest options :sha256)))

(defmethod engine :hmac+sha1
  [_]
  (hmac-engine :sha1))

(defmethod engine :hmac+sha256
  [_]
  (hmac-engine :sha256))

(defmethod engine :hmac+sha384
  [_]
  (hmac-engine :sha384))

(defmethod engine :hmac+sha512
  [_]
  (hmac-engine :sha512))

(defmethod engine :poly1305
  [options]
  (let [requested (:cipher options :aes)
        cipher (resolve-cipher-engine requested)]
    (when-not cipher
      (throw (ex-info (str "Unsupported Poly1305 cipher: " requested)
                      {:cipher requested})))
    (poly1305-engine cipher)))

(defmethod engine :poly1305+aes
  [_]
  (poly1305-engine (resolve-cipher-engine :aes)))

(defmethod engine :poly1305+twofish
  [_]
  (throw (ex-info "Unsupported Poly1305 cipher: :twofish"
                  {:cipher :twofish})))

(defmethod engine :poly1305+serpent
  [_]
  (throw (ex-info "Unsupported Poly1305 cipher: :serpent"
                  {:cipher :serpent})))

(defn- hash-plain-data [input engine]
  (-reset engine)
  (-update engine input 0 (count input))
  (-end engine))

(defn- hash-stream-data [input engine]
  (-reset engine)
  (let [buffer (byte-array 5120)]
    (try
      (loop []
        (let [readed (.read input buffer 0 5120)]
          (when-not (= readed -1)
            (-update engine buffer 0 readed)
            (recur))))
      (catch Throwable e
        (-reset engine)
        (throw e)))
    (-end engine)))

(defn- verify-plain-data [input signature engine]
  (let [sig (hash-plain-data input engine)]
    (bytes/equals? sig signature)))

(defn- verify-stream [input signature engine]
  (let [sig (hash-stream-data input engine)]
    (bytes/equals? sig signature)))

(extend-protocol IMac
  String
  (-hash [input engine]
    (hash-plain-data (codecs/str->bytes input) engine))
  (-verify [input signature engine]
    (verify-plain-data (codecs/str->bytes input) signature engine))

  InputStream
  (-hash [input engine]
    (hash-stream-data input engine))
  (-verify [input signature engine]
    (verify-stream input signature engine))

  java.io.File
  (-hash [input engine]
    (with-open [stream (io/input-stream input)]
      (hash-stream-data stream engine)))
  (-verify [input signature engine]
    (with-open [stream (io/input-stream input)]
      (verify-stream stream signature engine)))

  Object
  (-hash [input engine]
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
              (str "Unsupported MAC input: " (class input))))))
  (-verify [input signature engine]
    (cond
      (bytes/bytes? input)
      (verify-plain-data input signature engine)

      (instance? java.net.URL input)
      (with-open [stream (io/input-stream input)]
        (verify-stream stream signature engine))

      (instance? java.net.URI input)
      (with-open [stream (io/input-stream input)]
        (verify-stream stream signature engine))

      :else
      (throw (IllegalArgumentException.
              (str "Unsupported MAC input: " (class input)))))))

(defn hash
  "Generate hmac digest for arbitrary
  input data, a secret key and hash algorithm.

  If algorithm is not supplied, sha256
  will be used as default value."
  [input engine-or-options]
  (if (satisfies? IEngine engine-or-options)
    (-hash input engine-or-options)
    (let [engine (engine engine-or-options)]
      (-init engine engine-or-options)
      (-hash input engine))))

(defn verify
  "Verify hmac for artbitrary input and signature."
  [input signature engine-or-options]
  (let [signature (codecs/to-bytes signature)]
    (if (satisfies? IEngine engine-or-options)
      (-verify input signature engine-or-options)
      (let [engine (engine engine-or-options)]
        (-init engine engine-or-options)
        (-verify input signature engine)))))
