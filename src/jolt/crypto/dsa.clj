;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: retained the Buddy protocols and algorithm names
;; over the OpenSSL-backed java.security.Signature shim, with streams closed.

(ns jolt.crypto.dsa
  "Digital Signature Algorithms."
  (:refer-clojure :exclude [resolve])
  (:require [clojure.java.io :as io]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs])
  (:import [java.io InputStream]
           [java.security Signature]))

(declare ->SignatureEngine)

(def ^:no-doc +algorithms+
  {:rsassa-pss+sha256 #(->SignatureEngine (Signature/getInstance "SHA256withRSAandMGF1"))
   :rsassa-pss+sha384 #(->SignatureEngine (Signature/getInstance "SHA384withRSAandMGF1"))
   :rsassa-pss+sha512 #(->SignatureEngine (Signature/getInstance "SHA512withRSAandMGF1"))
   :rsassa-pkcs15+sha256 #(->SignatureEngine (Signature/getInstance "SHA256withRSA"))
   :rsassa-pkcs15+sha384 #(->SignatureEngine (Signature/getInstance "SHA384withRSA"))
   :rsassa-pkcs15+sha512 #(->SignatureEngine (Signature/getInstance "SHA512withRSA"))
   :ecdsa+sha256 #(->SignatureEngine (Signature/getInstance "SHA256withECDSA"))
   :ecdsa+sha384 #(->SignatureEngine (Signature/getInstance "SHA384withECDSA"))
   :ecdsa+sha512 #(->SignatureEngine (Signature/getInstance "SHA512withECDSA"))
   :eddsa #(->SignatureEngine (Signature/getInstance "EdDSA"))})

(def ^:no-doc ^:static +buffer-size+ 5120)

(defprotocol IEngine
  (-init [_ options] "Initialize signature.")
  (-update [_ input offset length] "Update signature state.")
  (-end [_ signature?] "Return the computed signature or verification result."))

(defprotocol ISignature
  "Default interface for all supported signature input types."
  (-sign [input engine] "Make signature.")
  (-verify [input signature engine] "Verify signature."))

(defn- resolve [signer]
  (cond
    (keyword? signer)
    (when-let [factory (get +algorithms+ signer)]
      (factory))

    (satisfies? IEngine signer)
    signer

    (fn? signer)
    (signer)))

(defrecord SignatureEngine [signature]
  IEngine
  (-init [_ options]
    (let [key (:key options)]
      (if (:verify options false)
        (.initVerify signature key)
        (if-let [prng (:prng options)]
          (.initSign signature key prng)
          (.initSign signature key))))
    nil)

  (-update [_ input offset length]
    (.update signature input offset length)
    nil)

  (-end [_ signature?]
    (if signature?
      (.verify signature signature?)
      (.sign signature))))

(defn- sign-plain-data [input engine]
  (-update engine input 0 (count input))
  (-end engine nil))

(defn- verify-plain-data [input signature engine]
  (-update engine input 0 (count input))
  (-end engine signature))

(defn- sign-stream [stream engine]
  (let [buffer (byte-array +buffer-size+)]
    (loop []
      (let [amount (.read stream buffer 0 +buffer-size+)]
        (when-not (= amount -1)
          (-update engine buffer 0 amount)
          (recur))))
    (-end engine nil)))

(defn- verify-stream [stream signature engine]
  (let [buffer (byte-array +buffer-size+)]
    (loop []
      (let [amount (.read stream buffer 0 +buffer-size+)]
        (when-not (= amount -1)
          (-update engine buffer 0 amount)
          (recur))))
    (-end engine signature)))

(extend-protocol ISignature
  String
  (-sign [input engine]
    (sign-plain-data (codecs/str->bytes input) engine))
  (-verify [input signature engine]
    (verify-plain-data (codecs/str->bytes input) signature engine))

  InputStream
  (-sign [input engine]
    (sign-stream input engine))
  (-verify [input signature engine]
    (verify-stream input signature engine))

  java.io.File
  (-sign [input engine]
    (with-open [stream (io/input-stream input)]
      (sign-stream stream engine)))
  (-verify [input signature engine]
    (with-open [stream (io/input-stream input)]
      (verify-stream stream signature engine)))

  Object
  (-sign [input engine]
    (cond
      (bytes/bytes? input)
      (sign-plain-data input engine)

      (instance? java.net.URL input)
      (with-open [stream (io/input-stream input)]
        (sign-stream stream engine))

      (instance? java.net.URI input)
      (with-open [stream (io/input-stream input)]
        (sign-stream stream engine))

      :else
      (throw (IllegalArgumentException.
              (str "Unsupported signature input: " (class input))))))
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
              (str "Unsupported signature input: " (class input)))))))

(defn sign
  [input {:keys [alg key prng] :as options}]
  (let [engine (resolve alg)]
    (when-not engine
      (throw (ex-info (str "Unsupported signature algorithm: " alg)
                      {:algorithm alg})))
    (-init engine (assoc options :verify false :key key :prng prng))
    (-sign input engine)))

(defn verify
  [input signature {:keys [alg key] :as options}]
  (let [engine (resolve alg)]
    (when-not engine
      (throw (ex-info (str "Unsupported signature algorithm: " alg)
                      {:algorithm alg})))
    (-init engine (assoc options :verify true :key key))
    (-verify input signature engine)))
