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
;; Modified in 2026 for Jolt: replaced Bouncy Castle class assertions with
;; tagged-key behavior, added EdDSA, reader, certificate, DER, malformed-input,
;; and independent RFC 3394 known-answer coverage.

(ns jolt.crypto.keys-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer :all]
            [jolt.crypto :as crypto]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.keys :as keys]
            [jolt.crypto.keys.pem :as pem]
            [jolt.crypto.nonce :as nonce])
  (:import [java.security KeyFactory Signature]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]))

(defn- fixture [name]
  (str "test/_files/" name))

(defn- fixture-text [name]
  (slurp (fixture name)))

(defn- check-private-key [key algorithm factory-name]
  (is (keys/private-key? key))
  (is (false? (keys/public-key? key)))
  (is (= algorithm (.getAlgorithm key)))
  (is (= factory-name (crypto/key-type key)))
  (is (= "PKCS#8" (.getFormat key)))
  (is (pos? (alength (.getEncoded key))))
  (let [factory (KeyFactory/getInstance factory-name)
        decoded (.generatePrivate factory (PKCS8EncodedKeySpec. (.getEncoded key)))]
    (is (= algorithm (.getAlgorithm decoded)))
    (is (= "PKCS#8" (.getFormat decoded)))
    (is (bytes/equals? (.getEncoded key) (.getEncoded decoded)))))

(defn- check-public-key [key algorithm factory-name]
  (is (keys/public-key? key))
  (is (false? (keys/private-key? key)))
  (is (= algorithm (.getAlgorithm key)))
  (is (= factory-name (crypto/key-type key)))
  (is (= "X.509" (.getFormat key)))
  (is (pos? (alength (.getEncoded key))))
  (let [factory (KeyFactory/getInstance factory-name)
        decoded (.generatePublic factory (X509EncodedKeySpec. (.getEncoded key)))]
    (is (= algorithm (.getAlgorithm decoded)))
    (is (= "X.509" (.getFormat decoded)))
    (is (bytes/equals? (.getEncoded key) (.getEncoded decoded)))))

(deftest read-private-pem-keys
  (doseq [[filename algorithm passphrase factory-name]
          [["privkey.3des.rsa.pem" "RSA" "secret" "RSA"]
           ["privkey.rsa.pem" "RSA" nil "RSA"]
           ["privkey.pkcs8.3des.rsa.pem" "RSA" "secret" "RSA"]
           ["privkey.pkcs8.rsa.pem" "RSA" nil "RSA"]
           ["privkey.3des.dsa.pem" "DSA" "secret" "DSA"]
           ["privkey.ecdsa.pem" "EC" "secret" "EC"]
           ["privkey.ed25519.pem" "EdDSA" nil "Ed25519"]
           ["privkey.ed448.pem" "EdDSA" nil "Ed448"]]]
    (testing filename
      (check-private-key (keys/private-key (fixture filename) passphrase)
                         algorithm factory-name))))

(deftest read-public-pem-keys-and-certificates
  (doseq [[filename algorithm factory-name]
          [["pubkey.3des.rsa.pem" "RSA" "RSA"]
           ["pubkey.X509.rsa.pem" "RSA" "RSA"]
           ["pubkey.3des.dsa.pem" "DSA" "DSA"]
           ["pubkey.ecdsa.pem" "EC" "EC"]
           ["pubkey.ed25519.pem" "EdDSA" "Ed25519"]
           ["pubkey.ed448.pem" "EdDSA" "Ed448"]]]
    (testing filename
      (check-public-key (keys/public-key (fixture filename)) algorithm factory-name))))

(deftest read-keys-from-strings-and-readers
  (testing "public key string"
    (check-public-key (keys/str->public-key (fixture-text "pubkey.ecdsa.pem")) "EC" "EC"))
  (testing "unencrypted private key string"
    (check-private-key (keys/str->private-key (fixture-text "privkey.rsa.pem")) "RSA" "RSA"))
  (testing "encrypted private key string"
    (check-private-key (keys/str->private-key (fixture-text "privkey.3des.rsa.pem") "secret")
                       "RSA" "RSA"))
  (testing "Ed448 strings"
    (check-private-key (keys/str->private-key (fixture-text "privkey.ed448.pem")) "EdDSA" "Ed448")
    (check-public-key (keys/str->public-key (fixture-text "pubkey.ed448.pem")) "EdDSA" "Ed448"))
  (testing "reader inputs"
    (check-private-key (pem/read-privkey (io/reader (fixture "privkey.3des.dsa.pem")) "secret")
                       "DSA" "DSA")
    (check-public-key (pem/read-pubkey (java.io.StringReader. (fixture-text "pubkey.3des.rsa.pem")))
                      "RSA" "RSA")
    (check-public-key (pem/read-pubkey (io/reader (fixture "pubkey.X509.rsa.pem"))) "RSA" "RSA")))

(deftest eddsa-key-factories-respect-the-concrete-key-type
  (let [ed25519-private (keys/private-key (fixture "privkey.ed25519.pem"))
        ed25519-public (keys/public-key (fixture "pubkey.ed25519.pem"))
        ed448-private (keys/private-key (fixture "privkey.ed448.pem"))
        ed448-public (keys/public-key (fixture "pubkey.ed448.pem"))]
    (is (thrown? clojure.lang.ExceptionInfo
                 (.generatePrivate (KeyFactory/getInstance "Ed448")
                                   (PKCS8EncodedKeySpec. (.getEncoded ed25519-private)))))
    (is (thrown? clojure.lang.ExceptionInfo
                 (.generatePrivate (KeyFactory/getInstance "Ed25519")
                                   (PKCS8EncodedKeySpec. (.getEncoded ed448-private)))))
    (is (thrown? clojure.lang.ExceptionInfo
                 (.generatePublic (KeyFactory/getInstance "Ed448")
                                  (X509EncodedKeySpec. (.getEncoded ed25519-public)))))
    (is (thrown? clojure.lang.ExceptionInfo
                 (.generatePublic (KeyFactory/getInstance "Ed25519")
                                  (X509EncodedKeySpec. (.getEncoded ed448-public)))))
    (is (= "EdDSA" (.getAlgorithm
                    (.generatePrivate (KeyFactory/getInstance "EdDSA")
                                      (PKCS8EncodedKeySpec. (.getEncoded ed448-private))))))))

(deftest encrypted-pem-requires-the-correct-passphrase
  (doseq [filename ["privkey.3des.rsa.pem"
                    "privkey.pkcs8.3des.rsa.pem"
                    "privkey.3des.dsa.pem"]]
    (testing filename
      (is (thrown? clojure.lang.ExceptionInfo (keys/private-key (fixture filename))))
      (is (thrown? clojure.lang.ExceptionInfo
                   (keys/str->private-key (fixture-text filename))))
      (is (thrown? clojure.lang.ExceptionInfo (keys/private-key (fixture filename) "secret2")))))
  (testing "failures do not poison a later valid decode"
    (dotimes [_ 5]
      (is (thrown? clojure.lang.ExceptionInfo
                   (keys/private-key (fixture "privkey.3des.rsa.pem") "wrong"))))
    (check-private-key (keys/private-key (fixture "privkey.3des.rsa.pem") "secret") "RSA" "RSA")))

(deftest malformed-and-wrong-type-pem-inputs-throw
  (doseq [read-key [keys/str->private-key keys/str->public-key]]
    (is (thrown? clojure.lang.ExceptionInfo (read-key "not a PEM key")))
    (is (thrown? clojure.lang.ExceptionInfo (read-key ""))))
  (is (thrown? clojure.lang.ExceptionInfo
               (keys/str->private-key (fixture-text "pubkey.ecdsa.pem"))))
  (is (thrown? clojure.lang.ExceptionInfo
               (keys/str->public-key (fixture-text "privkey.rsa.pem"))))
  (is (thrown? clojure.lang.ExceptionInfo
               (keys/str->private-key (fixture-text "pubkey.X509.rsa.pem")))))

(deftest key-predicates-reject-non-keys
  (doseq [value [nil "key" {} [] (byte-array 0) 42]]
    (is (false? (keys/private-key? value)))
    (is (false? (keys/public-key? value)))))

(deftest loaded-keys-sign-and-verify-with-existing-algorithms
  (doseq [[private-file public-file algorithm passphrase]
          [["privkey.3des.rsa.pem" "pubkey.3des.rsa.pem" "SHA256withRSA" "secret"]
           ["privkey.ecdsa.pem" "pubkey.ecdsa.pem" "SHA256withECDSA" nil]
           ["privkey.ed25519.pem" "pubkey.ed25519.pem" "Ed25519" nil]]]
    (testing algorithm
      (let [private-key (keys/private-key (fixture private-file) passphrase)
            public-key (keys/public-key (fixture public-file))
            message (codecs/str->bytes "PEM keys retain signature behavior")
            signature (.sign (doto (Signature/getInstance algorithm)
                               (.initSign private-key)
                               (.update message)))]
        (is (true? (.verify (doto (Signature/getInstance algorithm)
                              (.initVerify public-key)
                              (.update message))
                            signature)))
        (is (false? (.verify (doto (Signature/getInstance algorithm)
                               (.initVerify public-key)
                               (.update (codecs/str->bytes "tampered")))
                             signature)))))))

(deftest aes-key-wrap-rfc3394-known-answers
  (doseq [[kek key wrapped]
          [["000102030405060708090a0b0c0d0e0f"
            "00112233445566778899aabbccddeeff"
            "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"]
           ["000102030405060708090a0b0c0d0e0f1011121314151617"
            "00112233445566778899aabbccddeeff0001020304050607"
            "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"]
           ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f"
            "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"]]]
    (let [kek (codecs/hex->bytes kek)
          key (codecs/hex->bytes key)
          wrapped (codecs/hex->bytes wrapped)]
      (is (bytes/equals? wrapped (keys/wrap key kek)))
      (is (bytes/equals? wrapped (keys/wrap key kek :aes)))
      (is (bytes/equals? key (keys/unwrap wrapped kek)))
      (is (bytes/equals? key (keys/unwrap wrapped kek :aes))))))

(deftest aes-key-wrap-round-trips-all-kek-sizes
  (doseq [secret-size [16 24 32]
          key-size [16 24 32]]
    (let [secret (nonce/random-bytes secret-size)
          key (nonce/random-bytes key-size)
          wrapped (keys/wrap key secret)]
      (is (= (+ key-size 8) (alength wrapped)))
      (is (bytes/equals? key (keys/unwrap wrapped secret))))))

(deftest aes-key-wrap-rejects-invalid-inputs
  (let [secret (nonce/random-bytes 16)
        key (nonce/random-bytes 32)
        wrapped (keys/wrap key secret)]
    (doseq [bad-secret [(nonce/random-bytes 15) (nonce/random-bytes 64)]]
      (is (thrown? clojure.lang.ExceptionInfo (keys/wrap key bad-secret)))
      (is (thrown? clojure.lang.ExceptionInfo (keys/unwrap wrapped bad-secret))))
    (doseq [length [0 7 8 15 31]]
      (is (thrown? clojure.lang.ExceptionInfo (keys/wrap (nonce/random-bytes length) secret))))
    (doseq [length [0 8 15 31]]
      (is (thrown? clojure.lang.ExceptionInfo (keys/unwrap (nonce/random-bytes length) secret))))
    (is (thrown? clojure.lang.ExceptionInfo (keys/unwrap wrapped (nonce/random-bytes 16))))
    (aset-byte wrapped 0 (unchecked-byte (bit-xor (aget wrapped 0) 1)))
    (is (thrown? clojure.lang.ExceptionInfo (keys/unwrap wrapped secret)))))
