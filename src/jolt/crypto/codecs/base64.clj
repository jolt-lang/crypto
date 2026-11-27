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
;; Modified in 2026 for Jolt: replaced Apache Commons Codec with the strict
;; jolt.crypto.codecs implementations and added the URL-safe decode arity.

(ns jolt.crypto.codecs.base64
  "Util functions for conversion between strings, bytes, and Base64.

  DEPRECATED: replaced by functions in `jolt.crypto.codecs`"
  (:require [jolt.crypto.codecs :as codecs]))

(defn encode
  "Encode data to byte array base64. Accepts String and byte array as argument."
  {:deprecated "1.7.1"}
  ([data]
   (encode data false))
  ([data urlsafe?]
   (codecs/bytes->b64 (codecs/to-bytes data) urlsafe?)))

(defn decode
  "Decode base64 data into byte array. Accepts String and byte array as input."
  {:deprecated "1.7.1"}
  ([data]
   (decode data false))
  ([data urlsafe?]
   (codecs/b64->bytes (codecs/to-bytes data) urlsafe?)))
