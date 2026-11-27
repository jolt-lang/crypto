;; Copyright 2013-2016 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle dispatch types with
;; OpenSSL engine classes, a block-size fallback, and the existing CSPRNG.

(ns jolt.crypto.nonce
  "Namespace dedicated to provide an abstraction
  for generate a valid secure nonce values.

  By convenience, it also exposes additional functions
  for generate random iv/salts."
  (:require [jolt.crypto :as crypto]
            [jolt.crypto.crypto :as cipher]))

(defn random-bytes
  "Generate a byte array of specified length with random
  bytes taken from secure random number generator.
  This method should be used to generate a random
  iv/salt or arbitrary length."
  ([numbytes]
   (crypto/random-bytes numbytes))
  ([numbytes sr]
   (let [buffer (byte-array numbytes)]
     (.nextBytes sr buffer)
     buffer)))

(defn random-nonce
  "Generate a secure nonce based on current time
  and additional random data obtained from secure random
  generator. The minimum value is 8 bytes, and recommended
  minimum value is 32."
  ([numbytes]
   (random-nonce numbytes nil))
  ([numbytes sr]
   (let [buffer (java.nio.ByteBuffer/allocate numbytes)]
     (.putLong buffer (System/currentTimeMillis))
     (.put buffer (if sr
                    (random-bytes (.remaining buffer) sr)
                    (random-bytes (.remaining buffer))))
     (.array buffer))))

(defmulti for-engine
  "Generate an appropriate IV or nonce for a cipher engine."
  class)

(defmethod for-engine :default [engine]
  (random-bytes (.getBlockSize engine)))

(defmethod for-engine cipher/OpenSSLBlockCipher [_]
  (random-bytes 16))

(defmethod for-engine cipher/OpenSSLStreamCipher [_]
  (random-bytes 8))
