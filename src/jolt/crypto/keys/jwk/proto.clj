;; Copyright (c) 2014-2016 Andrey Antukh <niwi@niwi.nz>
;; Copyright (c) 2017 Denis Shilov <sxp@bk.ru>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle unsigned-integer helpers
;; with arbitrary-precision arithmetic and tagged-key dispatch.

(ns jolt.crypto.keys.jwk.proto
  (:require [jolt.crypto.codecs :as codecs]))

(defn calc-byte-length
  "Return the minimum unsigned big-endian byte length of a nonnegative integer."
  [bi]
  (when (neg? bi)
    (throw (IllegalArgumentException. "JWK integers must be unsigned")))
  (let [bits (loop [value bi length 0]
               (if (zero? value)
                 length
                 (recur (quot value 2) (inc length))))]
    (max 1 (quot (+ bits 7) 8))))

(defn b64str->bigint
  "Decode an unsigned big-endian Base64URL integer."
  [string]
  (let [bs (codecs/b64->bytes string true)]
    (reduce (fn [value octet]
              (+ (* value 256) (bit-and octet 0xff)))
            0 bs)))

(defn bytes->b64str [bs]
  (codecs/bytes->b64-str bs true))

(defn bigint->b64str
  "Encode a nonnegative integer in exactly length unsigned big-endian bytes."
  [length bi]
  (when (or (neg? length) (neg? bi))
    (throw (IllegalArgumentException. "JWK integers and lengths must be unsigned")))
  (let [output (byte-array length)]
    (loop [index (dec length) value bi]
      (when (and (neg? index) (pos? value))
        (throw (IllegalArgumentException. "Integer does not fit the requested JWK width")))
      (when-not (neg? index)
        (aset-byte output index (unchecked-byte (mod value 256)))
        (recur (dec index) (quot value 256))))
    (bytes->b64str output)))

(defn- key-dispatch [key]
  (if (jolt.host/table? key)
    (or (jolt.host/ref-get key :key-type)
        (jolt.host/ref-get key :algo))
    (class key)))

(defmulti public-key->jwk
  "Convert a tagged Jolt public key to a Clojure map representing a JWK."
  key-dispatch)

(defmulti jwk
  "Convert tagged Jolt private and public keys to a JWK map."
  (fn [private & _] (key-dispatch private)))

(defmulti jwk->private-key
  "Convert a JWK into a tagged Jolt PrivateKey."
  {:arglists '([jwk])}
  :kty)

(defmulti jwk->public-key
  "Convert a JWK into a tagged Jolt PublicKey."
  {:arglists '([jwk])}
  :kty)

(defmulti thumbprint
  "Calculate the JWK thumbprint according to RFC 7638."
  {:arglists '([jwk])}
  :kty)
