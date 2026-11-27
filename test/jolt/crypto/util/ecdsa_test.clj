;; Copyright (c) 2018 Andrey Antukh <niwi@niwi.nz>
;; Copyright 2012-2016 Connect2id Ltd.
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
;; Modified in 2026 for Jolt: added independent RFC expected encodings and strict
;; malformed-input, width, leading-zero, and round-trip regression coverage.

(ns jolt.crypto.util.ecdsa-test
  (:require [clojure.test :refer :all]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.util.ecdsa :as ecdsa]))

(def ^:private p256-concat
  (codecs/b64->bytes "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q" true))

(def ^:private p256-der
  (codecs/hex->bytes
   (str "304502200ed1215379636c483c2f7f155807d402a3b228033af97c7e17819ac3169ea665"
        "022100c50a07d38c3c70e5d8f12daf084a5480a66590c5f293509a8f3f7f8a83a354d5")))

(def ^:private p521-concat
  (codecs/b64->bytes
   "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"
   true))

(def ^:private p521-der
  (codecs/hex->bytes
   (str "308187024201dc0c81e7abc2d1e887e975f7697ad21a7dc001d915525b2df0ff531322ef47309d93986912356ca3d644e73e99966ac2a4f6488f8a183281df85ced1ac3fed776d"
        "02416f06692c0529d0803d98285c3d980496423c45f7c4aa51c1c74e3bc2a9107c098f2a8e8330ceee22af53cbdc9f036b9b161b496f444415ee90e5e894bcde3bf267")))

(deftest rfc7515-p256-transcoding
  (is (bytes/equals? p256-der (ecdsa/transcode-to-der p256-concat)))
  (is (bytes/equals? p256-concat (ecdsa/transcode-to-concat p256-der 64))))

(deftest rfc7515-p521-transcoding-preserves-coordinate-width
  (is (bytes/equals? p521-der (ecdsa/transcode-to-der p521-concat)))
  (let [transcoded (ecdsa/transcode-to-concat p521-der 132)]
    (is (= 132 (alength transcoded)))
    (is (bytes/equals? p521-concat transcoded))
    (is (zero? (aget transcoded 66)))))

(deftest leading-zero-and-high-bit-values-use-canonical-der
  (let [joined (byte-array (concat [0 1] (repeat 30 2) [0 0x80] (repeat 30 3)))
        der (ecdsa/transcode-to-der joined)]
    (is (= [0x30 0x43 0x02 0x1f 0x01] (vec (take 5 der))))
    (is (= [0x02 0x20 0x00 0x80]
           (mapv #(bit-and % 0xff) (take 4 (drop 35 der)))))
    (is (bytes/equals? joined (ecdsa/transcode-to-concat der 64)))))

(deftest invalid-concatenated-signatures-throw
  (doseq [length [0 1 3 63 65 255]]
    (is (thrown-with-msg? RuntimeException #"Invalid ECDSA signature format"
                          (ecdsa/transcode-to-der (byte-array length)))))
  (is (thrown-with-msg? RuntimeException #"Invalid ECDSA signature format"
                        (ecdsa/transcode-to-der (byte-array 256)))))

(deftest malformed-der-signatures-throw
  (doseq [der [(byte-array 0)
               (byte-array [0x30 0x06 0x02 0x01 0x01 0x02 0x01])
               (byte-array [0x31 0x06 0x02 0x01 0x01 0x02 0x01 0x01])
               (byte-array [0x30 0x82 0x06 0x02 0x01 0x01 0x02 0x01 0x01])
               (byte-array [0x30 0x06 0x01 0x01 0x01 0x02 0x01 0x01])
               (byte-array [0x30 0x06 0x02 0x01 0x01 0x01 0x01 0x01])
               (byte-array [0x30 0x07 0x02 0x01 0x01 0x02 0x01 0x01])
               (byte-array [0x30 0x06 0x02 0x02 0x01 0x02 0x01 0x01])
               (byte-array (concat (seq p256-der) [0]))]]
    (is (thrown-with-msg? RuntimeException #"Invalid ECDSA signature format"
                          (ecdsa/transcode-to-concat der 64)))))

(deftest concat-output-length-must-be-positive-and-even
  (doseq [length [-2 -1 0 1 63 65]]
    (is (thrown-with-msg? RuntimeException #"Invalid ECDSA signature format"
                          (ecdsa/transcode-to-concat p256-der length)))))
