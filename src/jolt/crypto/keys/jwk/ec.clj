;; Copyright (c) 2014-2018 Andrey Antukh <niwi@niwi.nz>
;; Copyright (c) 2017-2018 Denis Shilov <sxp@bk.ru>
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle EC specs with validated
;; OpenSSL points, fixed curve widths, and hand-built RFC 7638 JSON.

(ns jolt.crypto.keys.jwk.ec
  "JWK support for EC keys."
  (:require [jolt.crypto :as crypto]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.hash :as hash]
            [jolt.crypto.keys.jwk.proto :as proto]))

(defmulti jwkec->public-key :crv)
(defmulti jwkec->private-key :crv)

(defmethod proto/jwk->public-key "EC"
  [jwk]
  (jwkec->public-key jwk))

(defmethod proto/jwk->private-key "EC"
  [jwk]
  (jwkec->private-key jwk))

(def ^:private coordinate-widths
  {"P-256" 32 "P-384" 48 "P-521" 66 "secp256k1" 32})

(defn- decode-coordinate [jwk curve field]
  (let [coordinate (codecs/b64->bytes (get jwk field) true)
        expected (get coordinate-widths curve)
        actual (alength coordinate)]
    (when-not (= expected actual)
      (throw (ex-info "Invalid EC coordinate width"
                      {:curve curve :field field :expected expected :actual actual})))
    coordinate))

(defn- load-private [jwk curve]
  (let [x (decode-coordinate jwk curve :x)
        y (decode-coordinate jwk curve :y)
        d (decode-coordinate jwk curve :d)]
    (crypto/ec-private-from-parameters curve d x y)))

(defn- load-public [jwk curve]
  (let [x (decode-coordinate jwk curve :x)
        y (decode-coordinate jwk curve :y)]
    (crypto/ec-public-from-parameters curve x y)))

(doseq [curve ["P-256" "P-384" "P-521" "secp256k1"]]
  (defmethod jwkec->private-key curve [jwk] (load-private jwk curve))
  (defmethod jwkec->public-key curve [jwk] (load-public jwk curve)))

(defn- convert-public [parameters]
  {:kty "EC"
   :crv (:crv parameters)
   :x (proto/bytes->b64str (:x parameters))
   :y (proto/bytes->b64str (:y parameters))})

(defmethod proto/public-key->jwk "EC"
  [public]
  (convert-public (crypto/ec-public-parameters public)))

(defmethod proto/jwk "EC"
  [private public]
  (let [private-parameters (crypto/ec-private-parameters private)
        public-parameters (crypto/ec-public-parameters public)
        private-public (convert-public private-parameters)
        public-jwk (convert-public public-parameters)]
    (when-not (and (= (:crv private-public) (:crv public-jwk))
                   (bytes/equals? (:x private-parameters) (:x public-parameters))
                   (bytes/equals? (:y private-parameters) (:y public-parameters)))
      (throw (ex-info "Public key doesn't match private key"
                      {:expected (select-keys private-public [:crv :x :y])
                       :actual (select-keys public-jwk [:crv :x :y])})))
    (let [d (proto/b64str->bigint (proto/bytes->b64str (:d private-parameters)))
          width (get coordinate-widths (:crv private-parameters))]
      (assoc public-jwk :d (proto/bigint->b64str width d)))))

;; https://tools.ietf.org/html/rfc7638#section-3.2
(defmethod proto/thumbprint "EC"
  [jwk]
  (hash/sha256 (str "{\"crv\":\"" (:crv jwk)
                    "\",\"kty\":\"" (:kty jwk)
                    "\",\"x\":\"" (:x jwk)
                    "\",\"y\":\"" (:y jwk) "\"}")))
