;; Copyright (c) 2014-2018 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: retained the PEM and AES-wrap API using tagged
;; keys and OpenSSL; JWK conversion is implemented separately.

(ns jolt.crypto.keys
  "PEM key constructors, key predicates, and AES key wrapping."
  (:require [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.keys.pem :as pem])
  (:import java.io.StringReader))

(defn private-key
  "Private key constructor from a file path or reader."
  ([path]
   (private-key path nil))
  ([path passphrase]
   (pem/read-privkey path passphrase)))

(defn public-key
  "Public key constructor from a file path or reader."
  [path]
  (pem/read-pubkey path))

(defn str->public-key
  "Public key constructor from a PEM string."
  [keydata]
  (with-open [reader (StringReader. ^String keydata)]
    (pem/read-pubkey reader)))

(defn str->private-key
  "Private key constructor from a PEM string."
  ([keydata]
   (str->private-key keydata nil))
  ([keydata passphrase]
   (with-open [reader (StringReader. ^String keydata)]
     (pem/read-privkey reader passphrase))))

(defn- key-of-type? [tag value]
  (and (jolt.host/table? value)
       (= tag (jolt.host/ref-get value :jolt/type))))

(defn public-key?
  "Return true when value is a Jolt tagged PublicKey."
  [value]
  (boolean (key-of-type? :jolt.crypto/public-key value)))

(defn private-key?
  "Return true when value is a Jolt tagged PrivateKey."
  [value]
  (boolean (key-of-type? :jolt.crypto/private-key value)))

(defmulti wrap
  "Wrap key bytes using the selected algorithm (:aes by default)."
  (fn [& [_ _ algorithm]] algorithm)
  :default :aes)

(defmulti unwrap
  "Unwrap key bytes using the selected algorithm (:aes by default)."
  (fn [& [_ _ algorithm]] algorithm)
  :default :aes)

(defmethod wrap :aes
  [input secret & _]
  (openssl/aes-wrap input secret))

(defmethod unwrap :aes
  [input secret & _]
  (openssl/aes-unwrap input secret))
