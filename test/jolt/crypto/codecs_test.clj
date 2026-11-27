;; Copyright 2014-2020 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: ported to jolt.crypto, replaced JVM-specific
;; fixtures, and added malformed-input and binary regression coverage.

(ns jolt.crypto.codecs-test
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.codecs.base64 :as b64]))

(deftest string-byte-conversions
  (let [encoded (codecs/str->bytes "FooBar")]
    (is (bytes/bytes? encoded))
    (is (= "FooBar" (codecs/bytes->str encoded))))
  (is (= [104 0 105 0] (vec (codecs/str->bytes "hi" "UTF-16LE"))))
  (is (= "hi" (codecs/bytes->str (byte-array [104 0 105 0]) "UTF-16LE"))))

(deftest byte-array-coercions
  (let [data (byte-array [0 -1 127 -128])]
    (is (identical? data (codecs/to-bytes data)))
    (is (identical? data (codecs/->bytes data))))
  (is (= "hello" (codecs/bytes->str (codecs/to-bytes "hello"))))
  (is (= "hello" (codecs/bytes->str (codecs/->bytes "hello"))))
  (is (bytes/bytes? (codecs/to-bytes nil)))
  (is (zero? (count (codecs/to-bytes nil)))))

(deftest hexadecimal-codecs
  (testing "Buddy's string and byte-array round trips"
    (let [some-bytes (codecs/str->bytes "FooBar")
          decoded (codecs/hex->bytes (codecs/bytes->hex some-bytes))]
      (is (bytes/equals? decoded some-bytes))
      (is (= "FooBar" (codecs/bytes->str decoded))))
    (let [input (byte-array (range 10))]
      (is (bytes/equals? input (codecs/hex->bytes (codecs/bytes->hex input))))))
  (testing "encoding is lowercase and preserves signed bytes"
    (is (= "007f80ff" (codecs/bytes->hex (byte-array [0 127 -128 -1]))))
    (is (= [0 127 -128 -1] (vec (codecs/hex->bytes "007F80FF")))))
  (testing "malformed hexadecimal is rejected"
    (is (thrown? Exception (codecs/hex->bytes "abc")))
    (is (thrown? Exception (codecs/hex->bytes "0g")))
    (is (thrown? Exception (codecs/hex->bytes "zz")))))

(deftest base64-codecs
  (testing "standard Base64 round trips bytes and strings"
    (let [input (byte-array (range 10))]
      (is (bytes/equals? input (codecs/b64->bytes (codecs/bytes->b64 input)))))
    (is (= "hello world"
           (codecs/b64->str (codecs/bytes->b64 (codecs/str->bytes "hello world"))))))
  (testing "standard and URL-safe encodings have distinct literal forms"
    (let [input (byte-array [251 255])]
      (is (= "+/8=" (codecs/bytes->b64-str input)))
      (is (= "-_8" (codecs/bytes->b64-str input true)))
      (is (= [-5 -1] (vec (codecs/b64->bytes "+/8="))))
      (is (= [-5 -1] (vec (codecs/b64->bytes "-_8" true))))))
  (testing "URL-safe output without URL-specific characters remains decodable"
    (let [encoded (codecs/bytes->b64 (codecs/str->bytes "hello world2") true)]
      (is (= "hello world2" (codecs/b64->str encoded false)))))
  (testing "invalid Base64 is rejected"
    (doseq [invalid ["!!!" "a" "a===" "Zm9v="]]
      (is (thrown? Exception (codecs/b64->bytes invalid))))
    (is (thrown? Exception (codecs/b64->bytes "-_8" false)))))

(deftest deprecated-base64-api
  (testing "namespace encoder accepts strings and byte arrays"
    (is (= "Zm9v" (codecs/bytes->str (b64/encode "foo"))))
    (is (= "Zm9v" (codecs/bytes->str (b64/encode (codecs/str->bytes "foo") true))))
    (is (= "-_8" (codecs/bytes->str (b64/encode (byte-array [251 255]) true)))))
  (testing "namespace decoder supports both arities and returns byte arrays"
    (let [standard (b64/decode "Zm9v")
          urlsafe (b64/decode "-_8" true)]
      (is (bytes/bytes? standard))
      (is (bytes/bytes? urlsafe))
      (is (= "foo" (codecs/bytes->str standard)))
      (is (= [-5 -1] (vec urlsafe)))
      (is (thrown? Exception (b64/decode "!!!")))
      (is (thrown? Exception (b64/decode "-_8" false)))))
  (testing "codec aliases retain URL-safe behavior and deprecation metadata"
    (let [encoded (codecs/bytes->b64u (byte-array [251 255]))]
      (is (= "-_8" (codecs/bytes->str encoded)))
      (is (= [-5 -1] (vec (codecs/b64u->bytes encoded)))))
    (is (= "1.11" (:deprecated (meta #'codecs/bytes->b64u))))
    (is (= "1.11" (:deprecated (meta #'codecs/b64u->bytes))))
    (is (= "1.7.1" (:deprecated (meta #'b64/encode))))
    (is (= "1.7.1" (:deprecated (meta #'b64/decode))))))

(deftest signed-long-conversions
  (doseq [value [0 1 -1 42 -42 72623859790382856
                 -9223372036854775808 9223372036854775807]]
    (is (= value (codecs/bytes->long (codecs/long->bytes value)))))
  (is (= "0102030405060708" (codecs/bytes->hex (codecs/long->bytes 72623859790382856))))
  (is (= -2 (codecs/bytes->long (codecs/hex->bytes "fffffffffffffffe")))))

(deftest empty-binary-input
  (is (zero? (count (codecs/hex->bytes ""))))
  (is (= "" (codecs/bytes->hex (byte-array 0))))
  (is (zero? (count (codecs/bytes->b64 (byte-array 0)))))
  (is (zero? (count (codecs/b64->bytes ""))))
  (is (zero? (count (b64/decode ""))))
  (is (= "" (codecs/bytes->str (byte-array 0)))))
