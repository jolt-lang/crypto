;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: added deterministic boundary, small-buffer, and
;; malformed-input coverage.

(ns jolt.crypto.util.deflate-test
  (:require [clojure.test :as t]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as props]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.util.deflate :as df]))

(defspec deflate-compress-uncompress-spec 1000
  (props/for-all
   [data gen/bytes]
   (let [result1 (df/compress data)
         result2 (df/uncompress result1)]
     (t/is (bytes/equals? data result2)))))

(defspec deflate-compress-uncompress-zlib-spec 1000
  (props/for-all
   [data gen/bytes]
   (let [result1 (df/compress data {:nowrap false})
         result2 (df/uncompress result1 {:nowrap false})]
     (t/is (bytes/equals? data result2)))))

(defspec deflate-compress-uncompress-zlib-fallback-spec 1000
  (props/for-all
   [data gen/bytes]
   (let [result1 (df/compress data {:nowrap false})
         result2 (df/uncompress result1)]
     (t/is (bytes/equals? data result2)))))

(defn- round-trip [data]
  (let [raw (df/compress data)
        zlib (df/compress data {:nowrap false})]
    (t/is (bytes/equals? data (df/uncompress raw)))
    (t/is (bytes/equals? data (df/uncompress raw {:nowrap true})))
    (t/is (bytes/equals? data (df/uncompress zlib {:nowrap false})))
    (t/is (bytes/equals? data (df/uncompress zlib)))))

(t/deftest empty-input-round-trips
  (round-trip (byte-array 0)))

(t/deftest nul-containing-input-round-trips
  (round-trip (byte-array [0 1 0 2 0 -1 0])))

(t/deftest large-input-round-trips
  (round-trip (byte-array (map #(unchecked-byte (mod % 251))
                               (range (* 1024 1024))))))

(t/deftest repeated-byte-input-round-trips
  (round-trip (byte-array (repeat 65536 0x5a))))

(t/deftest small-buffers-round-trip
  (let [data (byte-array (map #(unchecked-byte (mod % 251)) (range 4096)))]
    (doseq [nowrap [true false]
            buffer-size [1 2 3 7 2048]]
      (let [compressed (df/compress data {:nowrap nowrap})]
        (t/is (bytes/equals? data (df/uncompress compressed
                                                 {:nowrap nowrap
                                                  :buffer-size buffer-size}))))))
  (let [data (byte-array (map int "zlib fallback through a one-byte buffer"))
        compressed (df/compress data {:nowrap false})]
    (t/is (bytes/equals? data (df/uncompress compressed {:buffer-size 1})))))

(t/deftest malformed-input-throws
  (t/is (thrown? java.io.IOException
                 (df/uncompress (byte-array [7]) {:nowrap true})))
  (t/is (thrown? java.io.IOException
                 (df/uncompress (byte-array [0 0]) {:nowrap false})))
  (t/is (thrown? java.io.IOException
                 (df/uncompress (byte-array [7])))))
