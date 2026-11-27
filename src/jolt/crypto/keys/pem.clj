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
;; Modified in 2026 for Jolt: replaced Bouncy Castle PEMParser and converters
;; with OpenSSL decoding into Jolt tagged-table keys.

(ns jolt.crypto.keys.pem
  "PEM private/public key reading backed by OpenSSL."
  (:require [clojure.java.io :as io]
            [jolt.crypto :as crypto]))

(defn- input-bytes [path-or-reader]
  (with-open [reader (io/reader path-or-reader)]
    (.getBytes (slurp reader) "UTF-8")))

(defn read-privkey
  "Read a traditional or PKCS#8 PEM private key from a path or reader."
  [path-or-reader passphrase]
  (crypto/decode-pem-private-key (input-bytes path-or-reader) passphrase))

(defn read-pubkey
  "Read a PEM public key or the subject public key from a certificate."
  [path-or-reader]
  (crypto/decode-pem-public-key (input-bytes path-or-reader)))
