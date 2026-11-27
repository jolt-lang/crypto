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
;; Modified in 2026 for Jolt: ported to OpenSSL-backed public engines, replaced
;; Twofish/Serpent cases with explicit rejection, and added independent
;; AES-Poly1305 known-answer, update/reset, failure, and native cleanup coverage.

(ns jolt.crypto.mac-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.hash :as hash]
            [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.mac :as mac]))

(def ^:private secret "my.secret.key")
(def ^:private poly-key
  (codecs/hex->bytes "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
(def ^:private poly-iv
  (codecs/hex->bytes "202122232425262728292a2b2c2d2e2f"))
(def ^:private poly-iv-other
  (codecs/hex->bytes "303132333435363738393a3b3c3d3e3f"))
(def ^:private poly-options
  {:key poly-key :iv poly-iv :alg :poly1305+aes})

(defn- hex [data]
  (codecs/bytes->hex data))

(defn- exception-data [f]
  (try
    (f)
    nil
    (catch Exception e
      (ex-data e))))

(deftest hmac-known-answer-vectors
  (doseq [[algorithm expected]
          [[:hmac+sha1 "8abe0fd691e3da3035f7b7ac91be45d99e942b9e"]
           [:hmac+sha256 "cb448b440c42ac8ad084fc8a8795c98f5b7802359c305eabd57ecdb20e248896"]
           [:hmac+sha384 (str "40292a79a280f609aef472272d2a2a0d148bfb83fa18fd2806440d07d16e31d9f0"
                              "d398891063c11f6c73891e6f646106")]
           [:hmac+sha512 (str "68c1687fa7cb5170ff800580a0cec29dc0ccb515aaf95587bdfe5c923730a7852e"
                              "2beefefd6be31d97aa612ad8b8569bba61ed2c339cd9b28409751b0b9e96a0")]]]
    (testing (str algorithm)
      (is (= expected (hex (mac/hash "a" {:key "b" :alg algorithm}))))))
  (testing "generic HMAC defaults to SHA-256"
    (is (bytes/equals? (mac/hash "foo" {:key secret :alg :hmac+sha256})
                       (mac/hash "foo" {:key secret :alg :hmac}))))
  (testing "generic HMAC accepts public digest engines and factories"
    (let [expected (mac/hash "foo" {:key secret :alg :hmac+sha256})]
      (is (bytes/equals? expected (mac/hash "foo" {:key secret :alg :hmac :digest :sha256})))
      (is (bytes/equals? expected (mac/hash "foo" {:key secret :alg :hmac
                                                   :digest (hash/resolve-digest-engine :sha256)})))
      (is (bytes/equals? expected (mac/hash "foo" {:key secret :alg :hmac
                                                   :digest #(hash/resolve-digest-engine :sha256)}))))))

(deftest hmac-large-key-rfc-4231-vector
  (let [key (codecs/hex->bytes (apply str (repeat 131 "aa")))
        data "Test Using Larger Than Block-Size Key - Hash Key First"
        expected "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"]
    (is (= expected (hex (mac/hash data {:key key :alg :hmac+sha256}))))
    (is (= expected (hex (mac/hash data {:key key :alg :hmac :digest :sha256}))))))

(deftest hmac-verification-and-input-types
  (is (true? (mac/verify "foo" (mac/hash "foo" {:key secret :alg :hmac+sha384})
                         {:key secret :alg :hmac+sha384})))
  (is (false? (mac/verify "foo" (mac/hash "bar" {:key secret :alg :hmac+sha384})
                          {:key secret :alg :hmac+sha384})))
  (is (false? (mac/verify "foo" (byte-array 48) {:key secret :alg :hmac+sha384})))
  (let [path "test/_files/pubkey.ecdsa.pem"
        file (io/file path)
        url (.toURL (.toURI file))
        uri (.toURI file)
        options {:key secret :alg :hmac+sha512}
        expected (mac/hash (codecs/str->bytes (slurp path)) options)]
    (with-open [stream (io/input-stream path)]
      (is (bytes/equals? expected (mac/hash stream options))))
    (with-open [stream (io/input-stream path)]
      (is (true? (mac/verify stream expected options))))
    (is (bytes/equals? expected (mac/hash file options)))
    (is (bytes/equals? expected (mac/hash url options)))
    (is (bytes/equals? expected (mac/hash uri options)))
    (is (true? (mac/verify file expected options)))
    (is (true? (mac/verify url expected options)))
    (is (true? (mac/verify uri expected options)))))

(deftest aes-poly1305-buddy-known-answer-vectors
  ;; Generated independently with buddy.core.mac/Bouncy Castle 1.78.1.
  (is (= "33f18339c8ae219a301ee186e0b2ca96"
         (hex (mac/hash "text" poly-options))))
  (is (= "d31dd57e62812cddabd1ccaa3c47979b"
         (hex (mac/hash "" poly-options))))
  (is (= "ebaab4867ef03979f01d40c0d8c06cea"
         (hex (mac/hash "AES-Poly1305 known answer" poly-options))))
  (is (bytes/equals? (mac/hash "text" poly-options)
                     (mac/hash "text" {:key poly-key :iv poly-iv :alg :poly1305 :cipher :aes}))))

(deftest aes-poly1305-verification-failures
  (let [signature (mac/hash "text" poly-options)
        wrong-key (aclone poly-key)]
    (aset-byte wrong-key 0 1)
    (is (true? (mac/verify "text" signature poly-options)))
    (is (false? (mac/verify "text" signature (assoc poly-options :key wrong-key))))
    (is (false? (mac/verify "text" signature (assoc poly-options :iv poly-iv-other))))
    (is (false? (mac/verify "other" signature poly-options)))
    (is (false? (mac/verify "text" (byte-array 16) poly-options)))
    (is (false? (mac/verify "text" (byte-array 15) poly-options)))
    (is (not (bytes/equals? (mac/hash "text" poly-options)
                            (mac/hash "text" (assoc poly-options :iv poly-iv-other)))))))

(deftest engine-update-offset-reset-and-input-snapshot
  (doseq [[options payload expected]
          [[{:key secret :alg :hmac+sha256} "a"
            "f710c2a740e7a07945b8a57351cbee6e4f215b02602511c06b088b8e69a9a013"]
           [poly-options "text" "33f18339c8ae219a301ee186e0b2ca96"]]]
    (let [engine (mac/engine options)]
      (mac/-init engine options)
      (mac/-update engine (codecs/str->bytes "discard") 0 7)
      (mac/-reset engine)
      (let [input (codecs/str->bytes (str "X" payload "Y"))]
        (mac/-update engine input 1 (count payload))
        (aset-byte input 1 (int \z)))
      (is (= expected (hex (mac/-end engine))) (str (:alg options)))
      (mac/-update engine (codecs/str->bytes payload) 0 (count payload))
      (is (= expected (hex (mac/-end engine))) (str "repeat " (:alg options))))))

(deftest poly1305-stream-file-url-and-uri
  (let [path "test/_files/pubkey.ecdsa.pem"
        file (io/file path)
        url (.toURL (.toURI file))
        uri (.toURI file)
        expected (mac/hash (codecs/str->bytes (slurp path)) poly-options)]
    (with-open [stream (io/input-stream path)]
      (is (bytes/equals? expected (mac/hash stream poly-options))))
    (with-open [stream (io/input-stream path)]
      (is (true? (mac/verify stream expected poly-options))))
    (is (bytes/equals? expected (mac/hash file poly-options)))
    (is (bytes/equals? expected (mac/hash url poly-options)))
    (is (bytes/equals? expected (mac/hash uri poly-options)))))

(deftest invalid-options-and-unsupported-ciphers-fail-explicitly
  (doseq [options [{:key (byte-array 31) :iv poly-iv :alg :poly1305+aes}
                   {:key poly-key :iv (byte-array 15) :alg :poly1305+aes}]]
    (is (some? (exception-data #(mac/hash "text" options)))))
  (doseq [cipher [:twofish :serpent]]
    (testing (str cipher)
      (is (= cipher (:cipher (exception-data
                              #(mac/engine {:alg :poly1305 :cipher cipher})))))))
  (is (= :twofish (:cipher (exception-data
                            #(mac/engine {:alg :poly1305 :cipher (fn [] :twofish)})))))
  (doseq [algorithm [:poly1305+twofish :poly1305+serpent]]
    (testing (str algorithm)
      (is (some? (exception-data #(mac/engine {:alg algorithm}))))))
  (is (some? (exception-data #(mac/engine {:alg :hmac :digest :not-a-digest})))))

(deftest poly1305-native-resources-are-freed-on-success-and-failure
  (let [cipher-frees (atom 0)
        pkey-frees (atom 0)
        md-frees (atom 0)
        cipher-free @#'openssl/c-cipher-ctx-free
        pkey-free @#'openssl/c-pkey-free
        md-free @#'openssl/c-md-ctx-free]
    (with-redefs [openssl/c-cipher-ctx-free (fn [ctx] (swap! cipher-frees inc) (cipher-free ctx))
                  openssl/c-pkey-free (fn [pkey] (swap! pkey-frees inc) (pkey-free pkey))
                  openssl/c-md-ctx-free (fn [ctx] (swap! md-frees inc) (md-free ctx))]
      (is (= "33f18339c8ae219a301ee186e0b2ca96"
             (hex (openssl/poly1305-aes-bytes poly-key poly-iv (codecs/str->bytes "text")))))
      (is (= [1 1 1] [@cipher-frees @pkey-frees @md-frees])))
    (reset! cipher-frees 0)
    (reset! pkey-frees 0)
    (reset! md-frees 0)
    (with-redefs [openssl/c-cipher-ctx-free (fn [ctx] (swap! cipher-frees inc) (cipher-free ctx))
                  openssl/c-pkey-free (fn [pkey] (swap! pkey-frees inc) (pkey-free pkey))
                  openssl/c-md-ctx-free (fn [ctx] (swap! md-frees inc) (md-free ctx))
                  openssl/c-poly1305-sign (fn [& _] 0)]
      (is (some? (exception-data
                  #(openssl/poly1305-aes-bytes poly-key poly-iv (codecs/str->bytes "text")))))
      (is (= [1 1 1] [@cipher-frees @pkey-frees @md-frees])))))

(deftest stream-hmac-matches-one-shot
  (let [data (byte-array (map unchecked-byte (range (* 3 1024 1024))))]
    (doseq [alg [:hmac+sha256 :hmac+sha512]]
      (testing (str alg)
        (is (= (codecs/bytes->hex (mac/hash data {:key secret :alg alg}))
               (codecs/bytes->hex (mac/hash (java.io.ByteArrayInputStream. data)
                                            {:key secret :alg alg}))))))))

(deftest stream-poly1305-matches-one-shot
  (let [data (byte-array (map unchecked-byte (range (* 3 1024 1024))))
        options {:key poly-key :iv poly-iv :alg :poly1305+aes}]
    (is (= (codecs/bytes->hex (mac/hash data options))
           (codecs/bytes->hex (mac/hash (java.io.ByteArrayInputStream. data) options))))
    (is (= (codecs/bytes->hex (openssl/poly1305-aes-bytes poly-key poly-iv data))
           (codecs/bytes->hex (mac/hash data options))))))
