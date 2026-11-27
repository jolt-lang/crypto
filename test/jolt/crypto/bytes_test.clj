;; Copyright (c) 2015-2020 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: ported to jolt.crypto and added byte-operation
;; regression coverage.

(ns jolt.crypto.bytes-test
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.crypto.bytes :as bytes]))

(deftest byte-array-predicate
  (is (true? (bytes/bytes? (byte-array 0))))
  (is (false? (bytes/bytes? "bytes")))
  (is (false? (bytes/bytes? [1 2 3])))
  (is (false? (bytes/bytes? nil))))

(deftest fill-mutates-whole-arrays-and-ranges
  (testing "whole-array fill preserves signed byte semantics"
    (let [input (byte-array [0 1 127 -128])]
      (bytes/fill! input -1)
      (is (= [-1 -1 -1 -1] (vec input)))))
  (testing "start/end select a half-open range"
    (let [input (byte-array [0 0 0 0 0])]
      (bytes/fill! input 7 :start 1 :end 3)
      (is (= [0 7 7 0 0] (vec input)))))
  (testing "offset/limit are aliases for start/end"
    (let [input (byte-array [0 0 0 0 0])]
      (bytes/fill! input 9 :offset 2 :limit 4)
      (is (= [0 0 9 9 0] (vec input)))))
  (testing "limit alone fills from the beginning"
    (let [input (byte-array [0 0 0 0])]
      (bytes/fill! input 3 :limit 2)
      (is (= [3 3 0 0] (vec input))))))

(deftest slice-and-copy-return-independent-arrays
  (let [input (byte-array [0 1 2 3 4])
        sliced (bytes/slice input 1 4)
        copied (bytes/copy input)]
    (is (= [1 2 3] (vec sliced)))
    (is (= [0 1 2 3 4] (vec copied)))
    (aset input 1 99)
    (is (= 1 (aget sliced 0)))
    (is (= 1 (aget copied 1)))
    (aset copied 0 88)
    (is (zero? (aget input 0)))))

(deftest constant-time-equality-results
  (is (true? (bytes/equals? (byte-array [0 -1 127 -128])
                            (byte-array [0 -1 127 -128]))))
  (is (false? (bytes/equals? (byte-array [1 2 3]) (byte-array [1 2 4]))))
  (is (false? (bytes/equals? (byte-array [1 2 3]) (byte-array [1 2]))))
  (is (true? (bytes/equals? "constant" "constant")))
  (is (false? (bytes/equals? "constant" "Constants"))))

(deftest concatenating-byte-arrays
  (is (= [1 2 3 3 4 5]
         (vec (bytes/concat (byte-array [1 2 3]) (byte-array [3 4 5])))))
  (is (= [0 -1 0 127 -128]
         (vec (bytes/concat (byte-array [0 -1]) (byte-array 0)
                            (byte-array [0 127 -128])))))
  (let [empty-result (bytes/concat)]
    (is (bytes/bytes? empty-result))
    (is (zero? (count empty-result)))))

(deftest concatenation-skips-nil-parts
  (doseq [[label parts expected]
          [["first" [nil (byte-array [1 2]) (byte-array [3])] [1 2 3]]
           ["middle" [(byte-array [1 2]) nil (byte-array [3])] [1 2 3]]
           ["last" [(byte-array [1 2]) (byte-array [3]) nil] [1 2 3]]]]
    (testing label
      (is (= expected (vec (apply bytes/concat parts))))))
  (testing "all nil and no parts both produce an empty byte array"
    (let [all-nil (bytes/concat nil nil nil)
          empty (bytes/concat)]
      (is (bytes/bytes? all-nil))
      (is (zero? (alength all-nil)))
      (is (bytes/bytes? empty))
      (is (zero? (alength empty))))))
