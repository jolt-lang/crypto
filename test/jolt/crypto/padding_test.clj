;; Copyright 2015 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: ported to jolt.crypto and added exact-byte,
;; empty-input, malformed-padding, and unsupported-algorithm coverage.

(ns jolt.crypto.padding-test
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.padding :as padding]))

(deftest pkcs7-padding
  (let [data (byte-array 10)]
    (bytes/fill! data 2)
    (is (= 4 (padding/pad! data 6)))
    (is (= [2 2 2 2 2 2 4 4 4 4] (vec data)))
    (is (padding/padded? data))
    (is (= (padding/count data) 4))
    (let [result (padding/unpad data :pkcs7)]
      (is (bytes/equals? result (bytes/slice data 0 6))))))

(deftest tbc-padding
  (let [data (byte-array 10)]
    (bytes/fill! data 2)
    (is (= 4 (padding/pad! data 6 :tbc)))
    (is (= [2 2 2 2 2 2 -1 -1 -1 -1] (vec data)))
    (is (padding/padded? data :tbc))
    (is (= (padding/count data :tbc) 4))
    (let [result (padding/unpad data :tbc)]
      (is (bytes/equals? result (bytes/slice data 0 6))))))

(deftest zerobyte-padding
  (let [data (byte-array 10)]
    (bytes/fill! data 2)
    (is (= 4 (padding/pad! data 6 :zerobyte)))
    (is (= [2 2 2 2 2 2 0 0 0 0] (vec data)))
    (is (padding/padded? data :zerobyte))
    (is (= (padding/count data :zerobyte) 4))
    (let [result (padding/unpad data :zerobyte)]
      (is (bytes/equals? result (bytes/slice data 0 6))))))

(deftest padding-engine-variants
  (testing "TBC complements an odd final bit with zero bytes"
    (let [data (byte-array [1 1 1 2 2 2])]
      (is (= 3 (padding/pad! data 3 :tbc)))
      (is (= [1 1 1 0 0 0] (vec data)))))
  (testing "TBC chooses an all-zero or all-ones block at offset zero"
    (let [data (byte-array 4)]
      (is (= 4 (padding/pad! data 0 :tbc)))
      (is (or (= [0 0 0 0] (vec data))
              (= [-1 -1 -1 -1] (vec data))))))
  (testing "PKCS7 supports padding lengths through 255 bytes"
    (doseq [[size expected] [[128 -128] [255 -1]]]
      (let [data (byte-array size)]
        (is (= expected (padding/pad! data 0)))
        (is (every? #(= expected %) data))
        (is (= size (padding/count data)))
        (is (zero? (count (padding/unpad data)))))))
  (testing "a zero-length padding operation leaves the input unchanged"
    (doseq [alg [:pkcs7 :tbc :zerobyte]]
      (let [data (byte-array [1 2 3])]
        (is (zero? (padding/pad! data 3 alg)))
        (is (= [1 2 3] (vec data)))))))

(deftest pad-is-side-effect-free
  (let [input (byte-array [1 2 3 0 0 0])
        output (padding/pad input 3)]
    (is (= [1 2 3 0 0 0] (vec input)))
    (is (= [1 2 3 3 3 3] (vec output)))
    (is (not (identical? input output)))
    (is (= [1 2 3] (vec (padding/unpad output))))))

(deftest malformed-padding-has-zero-count-and-unmodified-unpad
  (doseq [[alg inputs] [[:pkcs7 [[1 2 3 0]
                                [1 2 3 4]
                                [2 2 2 3]]]
                        [:tbc [[1 2 3 4]]]
                        [:zerobyte [[1 2 3 4]]]]]
    (doseq [input inputs]
      (let [data (byte-array input)
            result (padding/unpad data alg)]
        (is (zero? (padding/count data alg)))
        (is (false? (padding/padded? data alg)))
        (is (= input (vec result)))
        (is (not (identical? data result)))))))

(deftest empty-padding-has-zero-count-and-unmodified-unpad
  (doseq [alg [:pkcs7 :tbc :zerobyte]]
    (let [data (byte-array 0)
          result (padding/unpad data alg)]
      (is (zero? (padding/count data alg)))
      (is (false? (padding/padded? data alg)))
      (is (zero? (count result)))
      (is (not (identical? data result))))))

(deftest full-block-padding-is-removed
  (doseq [[alg input] [[:pkcs7 [2 2]]
                       [:tbc [-1 -1]]
                       [:zerobyte [0 0]]]]
    (let [data (byte-array input)]
      (is (= 2 (padding/count data alg)))
      (is (padding/padded? data alg))
      (is (zero? (count (padding/unpad data alg)))))))

(deftest padding-inspection-scans-every-input-position
  (doseq [[alg input expected-indices]
          [[:pkcs7 [4 4 4 4] [0 1 2 3]]
           [:pkcs7 [1 2 3 4] [0 1 2 3]]
           [:tbc [0 0 0 -1] [3 2 1 0]]
           [:tbc [0 0 0 1] [3 2 1 0]]
           [:zerobyte [0 0 0 1] [3 2 1 0]]]]
    (let [original-scan @#'padding/scan-indices
          scans (atom [])]
      (with-redefs-fn {#'padding/scan-indices
                       (fn [f init indices]
                         (swap! scans conj (vec indices))
                         (original-scan f init indices))}
        (fn []
          (padding/count (byte-array input) alg)
          (is (= [expected-indices] @scans)))))))

(deftest unsupported-padding-is-rejected
  (is (nil? (padding/padding-engine :unsupported)))
  (let [data (byte-array 4)]
    (is (thrown? Exception (padding/pad! data 1 :unsupported)))
    (is (thrown? Exception (padding/pad data 1 :unsupported)))
    (is (thrown? Exception (padding/count data :unsupported)))
    (is (thrown? Exception (padding/unpad data :unsupported)))
    (is (thrown? Exception (padding/padded? data :unsupported)))))
