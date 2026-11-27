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
;; Modified in 2026 for Jolt: raw byte arrays replace Bouncy Castle parameters,
;; reflection is removed, and OpenSSL constructs keys and validates key pairs.

(ns jolt.crypto.keys.jwk.eddsa
  "JWK support for Ed25519 and Ed448 keys."
  (:require [jolt.crypto :as crypto]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.keys.jwk.okp :as okp]
            [jolt.crypto.keys.jwk.proto :as proto]))

(defn pkcs8-key
  "Extract the raw Ed private key from a PKCS#8 PrivateKeyInfo encoding."
  [encoded len]
  (let [offset (if (and (= len 57)
                        (not= 73 (count encoded)))
                 17 16)]
    (bytes/slice encoded offset (+ offset len))))

(defn x509-key
  "Extract the raw Ed public key from an X.509 SPKI encoding."
  [encoded len]
  (bytes/slice encoded 12 (+ 12 len)))

(defn- curve-for-raw [raw]
  (case (count raw)
    32 "Ed25519"
    57 "Ed448"
    (throw (ex-info "Raw EdDSA keys must be 32 (Ed25519) or 57 (Ed448) bytes"
                    {:actual (count raw)}))))

(defn bc-ed-private-key
  "Construct a tagged EdDSA PrivateKey from raw 32/57-byte private key data."
  [raw]
  (crypto/ed-private-from-raw (curve-for-raw raw) raw))

(defn bc-ed-public-key
  "Construct a tagged EdDSA PublicKey from raw 32/57-byte public key data."
  [raw]
  (crypto/ed-public-from-raw (curve-for-raw raw) raw))

(defn- pubkey-25519 [jwk]
  (bc-ed-public-key (codecs/b64->bytes (:x jwk) true)))

(defn- pubkey-448 [jwk]
  (bc-ed-public-key (codecs/b64->bytes (:x jwk) true)))

(defn- verify-public-key! [private public]
  (let [public-bytes (crypto/ed-public-bytes public)
        derived-bytes (crypto/ed-derived-public-bytes private)]
    (when-not (bytes/equals? public-bytes derived-bytes)
      (throw (ex-info "Public key doesn't match private key"
                      {:expected (codecs/bytes->hex public-bytes)
                       :actual (codecs/bytes->hex derived-bytes)})))))

(defmethod okp/jwkokp->private-key "Ed25519"
  [jwk]
  (let [private (bc-ed-private-key (codecs/b64->bytes (:d jwk) true))
        public (pubkey-25519 jwk)]
    (verify-public-key! private public)
    private))

(defmethod okp/jwkokp->public-key "Ed25519"
  [jwk]
  (pubkey-25519 jwk))

(defmethod okp/jwkokp->private-key "Ed448"
  [jwk]
  (let [private (bc-ed-private-key (codecs/b64->bytes (:d jwk) true))
        public (pubkey-448 jwk)]
    (verify-public-key! private public)
    private))

(defmethod okp/jwkokp->public-key "Ed448"
  [jwk]
  (pubkey-448 jwk))

(defmethod proto/jwk "Ed25519"
  [private public]
  (verify-public-key! private public)
  {:kty "OKP"
   :crv "Ed25519"
   :d (proto/bytes->b64str (pkcs8-key (.getEncoded private) 32))
   :x (proto/bytes->b64str (x509-key (.getEncoded public) 32))})

(defmethod proto/jwk "Ed448"
  [private public]
  (verify-public-key! private public)
  {:kty "OKP"
   :crv "Ed448"
   :d (proto/bytes->b64str (pkcs8-key (.getEncoded private) 57))
   :x (proto/bytes->b64str (x509-key (.getEncoded public) 57))})

(defmethod proto/public-key->jwk "Ed25519"
  [public]
  {:kty "OKP"
   :crv "Ed25519"
   :x (proto/bytes->b64str (x509-key (.getEncoded public) 32))})

(defmethod proto/public-key->jwk "Ed448"
  [public]
  {:kty "OKP"
   :crv "Ed448"
   :x (proto/bytes->b64str (x509-key (.getEncoded public) 57))})
