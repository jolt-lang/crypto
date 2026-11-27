;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: ported to jolt.crypto and OpenSSL, and added
;; update-window, reset, input-type, HMAC, and unsupported-algorithm coverage.

(ns jolt.crypto.hash-test
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.java.io :as io]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.hash :as hash]
            [jolt.crypto.internal.openssl :as openssl]))

(def ^:private empty-vectors
  [[:md5 hash/md5
    "d41d8cd98f00b204e9800998ecf8427e"]
   [:sha1 hash/sha1
    "da39a3ee5e6b4b0d3255bfef95601890afd80709"]
   [:sha256 hash/sha256
    (str "e3b0c44298fc1c149afbf4c8996fb924"
         "27ae41e4649b934ca495991b7852b855")]
   [:sha384 hash/sha384
    (str "38b060a751ac96384cd9327eb1b1e36a"
         "21fdb71114be07434c0cc7bf63f6e1da"
         "274edebfe76f65fbd51ad2f14898b95b")]
   [:sha512 hash/sha512
    (str "cf83e1357eefb8bdf1542850d66d8007"
         "d620e4050b5715dc83f4a921d36ce9ce"
         "47d0d13c5d85f2b0ff8318d2877eec2f"
         "63b931bd47417a81a538327af927da3e")]
   [:sha3-256 hash/sha3-256
    (str "a7ffc6f8bf1ed76651c14756a061d662"
         "f580ff4de43b49fa82d80a4b80f8434a")]
   [:sha3-384 hash/sha3-384
    (str "0c63a75b845e4f7d01107d852e4c2485"
         "c51a50aaaa94fc61995e71bbee983a2a"
         "c3713831264adb47fb6bd1e058d5f004")]
   [:sha3-512 hash/sha3-512
    (str "a69f73cca23a9ac5c8b567dc185a756e"
         "97c982164fe25859e0d1dcc1475c80a6"
         "15b2123af1f5f94c11e3e9402c3ac558"
         "f500199d95b6d3e301758586281dcd26")]
   [:blake2b-512 hash/blake2b-512
    (str "786a02f742015903c6c6fd852552d272"
         "912f4740e15847618a86e217f71f5419"
         "d25e1031afee585313896444934eb04b"
         "903a685b1448b755d56f701afe9be2ce")]
   [:ripemd160 hash/ripemd160
    "9c1185a5c5e9fc54612808977ee8f548b2258d31"]])

(def ^:private digest-lengths
  {:md5 16
   :sha1 20
   :sha256 32
   :sha384 48
   :sha512 64
   :sha3-256 32
   :sha3-384 48
   :sha3-512 64
   :blake2b-512 64
   :ripemd160 20})

(def ^:private deferred-algorithms
  [:tiger :whirlpool
   :ripemd128 :ripemd256 :ripemd320
   :blake2b-128 :blake2b-256
   :blake3-128 :blake3-256 :blake3-512
   :skein-256 :skein-512 :skein-1024
   :sha224 :not-a-digest])

(defn- hex [data]
  (codecs/bytes->hex data))

(defn- exception-algorithm [f]
  (try
    (f)
    nil
    (catch Exception e
      (:algorithm (ex-data e)))))

(deftest supported-empty-digest-vectors
  (doseq [[algorithm named-digest expected] empty-vectors]
    (testing (str algorithm)
      (let [named-result (named-digest "")
            generic-result (hash/digest "" algorithm)
            internal-result (openssl/digest-bytes algorithm (byte-array 0))]
        (is (bytes/bytes? named-result))
        (is (bytes/bytes? generic-result))
        (is (bytes/bytes? internal-result))
        (is (= expected (hex named-result)))
        (is (= expected (hex generic-result)))
        (is (= expected (hex internal-result)))))))

(deftest md5-and-sha256-abc-vectors
  (is (= "900150983cd24fb0d6963f7d28e17f72"
         (hex (hash/md5 "abc"))))
  (is (= (str "ba7816bf8f01cfea414140de5dae2223"
              "b00361a396177a9cb410ff61f20015ad")
         (hex (hash/sha256 "abc"))))
  (is (= (hex (hash/sha256 "abc"))
         (hex (hash/sha256 (codecs/str->bytes "abc"))))))

(deftest blake2b-only-supports-64-byte-output
  (is (= (hex (hash/blake2b-512 ""))
         (hex (hash/blake2b "" 64))))
  (doseq [length [0 1 16 32 63 65 128]]
    (is (= :blake2b-512
           (exception-algorithm #(hash/blake2b "" length))))))

(deftest digest-lengths-and-hmac
  (doseq [[algorithm length] digest-lengths]
    (testing (str algorithm)
      (is (= length (openssl/digest-length algorithm)))
      (let [result (openssl/hmac-bytes algorithm
                                       (codecs/str->bytes "key")
                                       (codecs/str->bytes "data"))]
        (is (bytes/bytes? result))
        (is (= length (alength result))))))
  (is (= (str "f7bc83f430538424b13298e6aa6fb143"
              "ef4d59a14946175997479dbc2d1a3cd8")
         (hex (openssl/hmac-bytes :sha256
                                  (codecs/str->bytes "key")
                                  (codecs/str->bytes "The quick brown fox jumps over the lazy dog"))))))

(deftest low-level-engine-windows-and-reset
  (let [engine (hash/resolve-digest-engine :md5)]
    (hash/update! engine (codecs/str->bytes "a"))
    (hash/update! engine (codecs/str->bytes "XbcY") 1 2)
    (is (= "900150983cd24fb0d6963f7d28e17f72"
           (hex (hash/end! engine)))))
  (let [engine (hash/resolve-digest-engine :sha256)]
    (hash/update! engine (codecs/str->bytes "discard"))
    (hash/reset! engine)
    (hash/update! engine (codecs/str->bytes "abc"))
    (is (= (hex (hash/sha256 "abc")) (hex (hash/end! engine))))
    (hash/update! engine (codecs/str->bytes "abc"))
    (is (= (hex (hash/sha256 "abc")) (hex (hash/end! engine)))))
  (let [engine (hash/resolve-digest-engine :sha1)]
    (hash/update! engine (byte-array 0))
    (is (= "da39a3ee5e6b4b0d3255bfef95601890afd80709"
           (hex (hash/end! engine))))))

(deftest update-snapshots-input
  (let [engine (hash/resolve-digest-engine :sha256)
        input (codecs/str->bytes "abc")]
    (hash/update! engine input)
    (aset-byte input 0 120)
    (is (= (hex (hash/sha256 "abc")) (hex (hash/end! engine))))))

(deftest engine-resolution-accepts-engines-and-factories
  (let [engine (hash/resolve-digest-engine :sha256)]
    (is (identical? engine (hash/resolve-digest-engine engine)))
    (is (identical? engine (hash/resolve-digest-engine (fn [] engine))))))

(deftest file-stream-url-and-uri-digests
  (let [path "test/_files/pubkey.ecdsa.pem"
        file (io/file path)
        uri (.toURI file)
        url (.toURL uri)
        expected (str "7aa01e35e65701c9a9d8f71c4cbf056a"
                      "cddc9be17fdff06b4c7af1b0b34ddc29")]
    (with-open [stream (io/input-stream path)]
      (is (= expected (hex (hash/sha256 stream)))))
    (is (= expected (hex (hash/sha256 file))))
    (is (= expected (hex (hash/sha256 url))))
    (is (= expected (hex (hash/sha256 uri))))))

(deftest deferred-and-unknown-algorithms-fail-explicitly
  (doseq [algorithm deferred-algorithms]
    (testing (str algorithm)
      (is (nil? (hash/resolve-digest-engine algorithm)))
      (is (= algorithm (exception-algorithm #(hash/digest "" algorithm))))
      (is (= algorithm (exception-algorithm #(openssl/digest-length algorithm))))
      (is (= algorithm (exception-algorithm #(openssl/digest-bytes algorithm (byte-array 0)))))
      (is (= algorithm (exception-algorithm #(openssl/hmac-bytes algorithm (byte-array 0) (byte-array 0))))))))
