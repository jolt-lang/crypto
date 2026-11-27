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
;; Modified in 2026 for Jolt: added deterministic SecureRandom, timestamp,
;; requested-length, and block-size fallback coverage.

(ns jolt.crypto.nonce-test
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.crypto.nonce :as nonce]
            [jolt.host :as host])
  (:import javax.crypto.Cipher))

(def ^:private deterministic-random-tag
  :jolt.crypto.nonce-test/deterministic-random)

(__register-class-methods!
 deterministic-random-tag
 {"nextBytes" (fn [_ buffer & _]
                (dotimes [i (alength buffer)]
                  (aset buffer i (byte 42)))
                nil)})

(defn- deterministic-random []
  (host/tagged-table deterministic-random-tag))

(defn- big-endian-long [input]
  (reduce (fn [value b]
            (+ (* value 256) (bit-and b 0xff)))
          0
          (take 8 input)))

(deftest random-bytes-returns-the-requested-length
  (doseq [length [0 1 8 16 32 64]]
    (let [output (nonce/random-bytes length)]
      (is (bytes? output))
      (is (= length (alength output))))))

(deftest custom-secure-random-fills-random-bytes
  (let [output (nonce/random-bytes 8 (deterministic-random))]
    (is (= [42 42 42 42 42 42 42 42] (vec output)))))

(deftest default-random-nonce-uses-shared-csprng
  (let [calls (atom [])]
    (with-redefs [nonce/random-bytes
                  (fn
                    ([length]
                     (swap! calls conj [:default length])
                     (byte-array (repeat length 42)))
                    ([length _]
                     (swap! calls conj [:custom length])
                     (byte-array length)))]
      (let [output (nonce/random-nonce 12)]
        (is (= [[:default 4]] @calls))
        (is (= [42 42 42 42] (vec (drop 8 output))))))))

(deftest random-nonce-contains-big-endian-timestamp-and-random-suffix
  (let [before (System/currentTimeMillis)
        output (nonce/random-nonce 12 (deterministic-random))
        after (System/currentTimeMillis)]
    (is (= 12 (alength output)))
    (is (<= before (big-endian-long output) after))
    (is (= [42 42 42 42] (vec (drop 8 output))))))

(deftest random-nonce-requested-lengths
  (testing "an eight-byte nonce consists only of the timestamp"
    (let [output (nonce/random-nonce 8 (deterministic-random))]
      (is (= 8 (alength output)))
      (is (pos? (big-endian-long output)))))
  (doseq [length [16 32 64]]
    (is (= length (alength (nonce/random-nonce length)))))
  (testing "fewer than eight bytes cannot hold the timestamp"
    (is (thrown? Exception (nonce/random-nonce 7 (deterministic-random))))))

(deftest for-engine-uses-block-size-fallback
  (let [engine (Cipher/getInstance "AES/CBC/PKCS5Padding")
        output (nonce/for-engine engine)]
    (is (bytes? output))
    (is (= 16 (alength output)))))
