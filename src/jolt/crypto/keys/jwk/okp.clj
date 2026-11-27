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
;; Modified in 2026 for Jolt: hand-built canonical RFC 7638 JSON without Cheshire.

(ns jolt.crypto.keys.jwk.okp
  "Octet string key pair (OKP) support; see RFC 8037 section 2."
  (:require [jolt.crypto.hash :as hash]
            [jolt.crypto.keys.jwk.proto :as proto]))

(defmulti jwkokp->public-key :crv)
(defmulti jwkokp->private-key :crv)

(defmethod proto/jwk->public-key "OKP"
  [jwk]
  (jwkokp->public-key jwk))

(defmethod proto/jwk->private-key "OKP"
  [jwk]
  (jwkokp->private-key jwk))

;; https://tools.ietf.org/html/rfc8037#appendix-A.3
(defmethod proto/thumbprint "OKP"
  [jwk]
  (hash/sha256 (str "{\"crv\":\"" (:crv jwk)
                    "\",\"kty\":\"" (:kty jwk)
                    "\",\"x\":\"" (:x jwk) "\"}")))
