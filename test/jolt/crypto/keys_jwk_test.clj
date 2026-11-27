;; Copyright 2014-2018 Andrey Antukh <niwi@niwi.nz>
;; Copyright 2017-2018 Denis Shilov <sxp@bk.ru>
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle parameters and concrete
;; classes with raw bytes, tagged-key behavior, OpenSSL encodings, and signatures.

(ns jolt.crypto.keys-jwk-test
  (:require [clojure.test :refer :all]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.dsa :as dsa]
            [jolt.crypto.keys :as keys]
            [jolt.crypto.keys.jwk.eddsa :refer [bc-ed-private-key bc-ed-public-key pkcs8-key x509-key]]
            [jolt.crypto.keys.jwk.proto :as proto]
            [jolt.crypto.util.ecdsa :refer [transcode-to-der]])
  (:import [java.security KeyPairGenerator]
           [java.security.spec ECGenParameterSpec]))

(defn- b64u [value]
  (codecs/b64->bytes value true))

(defn- b64u-str [value]
  (codecs/bytes->b64-str value true))

(defn- load-pair [jwk]
  [(keys/jwk->public-key jwk)
   (keys/jwk->private-key jwk)])

(defn- fixture [name]
  (str "test/_files/" name))

(def ed25519-jwk-key
  {:kty "OKP"
   :crv "Ed25519"
   :d "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
   :x "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})

(def ed448-jwk-key
  {:kty "OKP"
   :crv "Ed448"
   :d "ZXIvEfZfm7XeT-kYVnwfIftaRZgz8Bo3b19BGMSJ2fdLaW4SRXH2sZjs2Arc8ewN3fuzWRjev3rs"
   :x "l1kFulHU9ZNQSbIxY7sYt6NCmg1S1UMm_LGJhx36fE5koFG_6esy9wX5Pt-J0xsK6aB4JFHxT3CA"})

(deftest ed25519-pem->jca->jwk
  (let [public (keys/public-key (fixture "pubkey.ed25519.pem"))
        private (keys/private-key (fixture "privkey.ed25519.pem"))
        jwk (keys/jwk private public)]
    (is (map? jwk))
    (is (= "OKP" (:kty jwk)))
    (is (= "Ed25519" (:crv jwk)))
    (let [public2 (keys/jwk->public-key jwk)
          private2 (keys/jwk->private-key jwk)]
      (is (= jwk (keys/jwk private2 public2))))))

(deftest ed25519-encoding
  (testing "raw private key and PKCS#8 extraction"
    (let [buf (b64u (:d ed25519-jwk-key))
          key (bc-ed-private-key buf)]
      (is (keys/private-key? key))
      (is (= "EdDSA" (.getAlgorithm key)))
      (is (bytes/equals? buf (pkcs8-key (.getEncoded key) 32)))))
  (testing "raw public key and SPKI extraction"
    (let [buf (b64u (:x ed25519-jwk-key))
          key (bc-ed-public-key buf)]
      (is (keys/public-key? key))
      (is (= "EdDSA" (.getAlgorithm key)))
      (is (bytes/equals? buf (x509-key (.getEncoded key) 32))))))

(deftest ed25519-jwk->jca->jwk
  (let [[public private] (load-pair ed25519-jwk-key)]
    (is (keys/private-key? private))
    (is (keys/public-key? public))
    (is (= ed25519-jwk-key (keys/jwk private public)))
    (is (= (dissoc ed25519-jwk-key :d) (keys/public-key->jwk public)))))

(deftest ed25519-thumbprint
  (is (= "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
         (b64u-str (keys/jwk-thumbprint ed25519-jwk-key)))))

(deftest ed25519-load-sign-verify
  (let [[public private] (load-pair ed25519-jwk-key)
        payload "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
        signature (dsa/sign payload {:alg :eddsa :key private})]
    (is (= "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
           (b64u-str signature)))
    (is (dsa/verify payload signature {:alg :eddsa :key public}))))

(deftest ed448-encoding
  (testing "raw private key and PKCS#8 extraction"
    (let [buf (b64u (:d ed448-jwk-key))
          key (bc-ed-private-key buf)]
      (is (keys/private-key? key))
      (is (= "EdDSA" (.getAlgorithm key)))
      (is (bytes/equals? buf (pkcs8-key (.getEncoded key) 57)))))
  (testing "raw public key and SPKI extraction"
    (let [buf (b64u (:x ed448-jwk-key))
          key (bc-ed-public-key buf)]
      (is (keys/public-key? key))
      (is (= "EdDSA" (.getAlgorithm key)))
      (is (bytes/equals? buf (x509-key (.getEncoded key) 57))))))

(deftest ed448-pem->jca->jwk
  (let [public (keys/public-key (fixture "pubkey.ed448.pem"))
        private (keys/private-key (fixture "privkey.ed448.pem"))
        jwk (keys/jwk private public)
        sig1 (dsa/sign "ABC" {:alg :eddsa :key private})]
    (is (map? jwk))
    (is (= "OKP" (:kty jwk)))
    (is (= "Ed448" (:crv jwk)))
    (is (dsa/verify "ABC" sig1 {:alg :eddsa :key public}))
    (let [public2 (keys/jwk->public-key jwk)
          private2 (keys/jwk->private-key jwk)
          jwk2 (keys/jwk private2 public2)
          private3 (keys/jwk->private-key jwk2)
          sig2 (dsa/sign "ABC" {:alg :eddsa :key private3})]
      (is (dsa/verify "ABC" sig2 {:alg :eddsa :key public}))
      (is (= jwk jwk2)))))

(deftest ed448-load-sign-verify
  (let [[public private] (load-pair ed448-jwk-key)
        payload "Buddy Loves Christmas!"
        signature (dsa/sign payload {:alg :eddsa :key private})]
    (is (= "mFUWr_F-Xgk0B53Ede9Z7nLOjIdlt5XapOV-BPtLQfznfqoW0ALfrFkaocWKvAV0ytRhTlvLSKiA_rxy6EuvyImPERv0duTf-HwF1gwULvH1MUQQ5Yr8nyymrJTBSHT1aDOCiXm8hCtPHTUbgnBQ0SgA"
           (b64u-str signature)))
    (is (dsa/verify payload signature {:alg :eddsa :key public}))))

(deftest mismatched-ed-private-public-keys-throw
  (doseq [jwk [ed25519-jwk-key ed448-jwk-key]]
    (let [mismatched (assoc jwk :x (if (= "Ed25519" (:crv jwk))
                                     (:x ed448-jwk-key)
                                     (:x ed25519-jwk-key)))]
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Public key doesn't match private key"
                            (keys/jwk->private-key mismatched))))
    (let [[public _] (load-pair jwk)
          other-public (keys/jwk->public-key (dissoc (if (= "Ed25519" (:crv jwk))
                                                       ed448-jwk-key ed25519-jwk-key) :d))
          private (keys/jwk->private-key jwk)]
      (is (some? public))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Public key doesn't match private key"
                            (keys/jwk private other-public))))))

(deftest raw-ed-constructors-reject-invalid-lengths
  (doseq [constructor [bc-ed-private-key bc-ed-public-key]
          length [0 31 33 56 58]]
    (is (thrown? clojure.lang.ExceptionInfo (constructor (byte-array length))))))

(deftest bi-encoding
  (testing "simple case"
    (let [bi (proto/b64str->bigint (:d ed25519-jwk-key))
          length (proto/calc-byte-length bi)]
      (is (= 32 length))
      (is (= (:d ed25519-jwk-key) (proto/bigint->b64str length bi)))))
  (testing "leading zeros"
    (let [by "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"
          bx "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"
          bi (proto/b64str->bigint by)
          length (proto/calc-byte-length (proto/b64str->bigint bx))]
      (is (= 66 length))
      (is (= 66 (alength (b64u by))))
      (is (= by (proto/bigint->b64str length bi))))))

(def rsa2048-jwk-key
  {:kty "RSA"
   :n "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
   :e "AQAB"
   :d "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"})

(deftest rsa-jwk->jca->jwk
  (let [[public private] (load-pair rsa2048-jwk-key)]
    (is (keys/private-key? private))
    (is (keys/public-key? public))
    (is (= "RSA" (.getAlgorithm private)))
    (is (= "RSA" (.getAlgorithm public)))
    (is (= "PKCS#8" (.getFormat private)))
    (is (= "X.509" (.getFormat public)))
    (is (= rsa2048-jwk-key (keys/jwk private public)))
    (is (= (dissoc rsa2048-jwk-key :d) (keys/public-key->jwk public)))))

(deftest rsa-load-sign-verify
  (let [[public private] (load-pair rsa2048-jwk-key)
        payload "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        signature (dsa/sign payload {:alg :rsassa-pkcs15+sha256 :key private})]
    (is (= "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
           (b64u-str signature)))
    (is (dsa/verify payload signature {:alg :rsassa-pkcs15+sha256 :key public}))))

(def rsa-short-d-crt-jwk
  {:kty "RSA"
   :n "DKE"
   :e "Bw"
   :d "3w"
   :p "PQ"
   :q "NQ"
   :dp "Kw"
   :dq "Dw"
   :qi "Jg"})

(deftest rsa-crt-bearing-key-round-trips-with-minimum-length-integers
  (let [[public private] (load-pair rsa-short-d-crt-jwk)
        round-trip (keys/jwk private public)
        encoded-d (b64u (:d round-trip))]
    (is (keys/public-key? public))
    (is (keys/private-key? private))
    (is (= rsa-short-d-crt-jwk round-trip))
    (is (= 1 (alength encoded-d)))
    (is (= 0xdf (bit-and (aget encoded-d 0) 0xff)))
    (doseq [field [:n :e :d :p :q :dp :dq :qi]]
      (is (not (zero? (aget (b64u (get round-trip field)) 0)))))))

(deftest inconsistent-or-incomplete-rsa-crt-fields-throw
  (doseq [[field value] [[:p "Pg"] [:q "Ng"] [:dp "LA"] [:dq "Dg"] [:qi "Jw"]]]
    (testing field
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid RSA CRT parameters"
                            (keys/jwk->private-key (assoc rsa-short-d-crt-jwk field value))))))
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Incomplete RSA CRT parameters"
                        (keys/jwk->private-key (dissoc rsa-short-d-crt-jwk :qi)))))

(deftest rsa-factor-recovery-failure-remains-closed
  (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Could not recover RSA factors from n/e/d"
                        (keys/jwk->private-key {:kty "RSA" :n "Ag" :e "Aw" :d "Bw"}))))

(def rsa-jwk-pubkey
  {:kty "RSA"
   :n "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
   :e "AQAB"
   :alg "RS256"
   :kid "2011-04-29"})

(deftest rsa-thumbprint
  (is (= "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
         (b64u-str (keys/jwk-thumbprint rsa-jwk-pubkey)))))

(def ec256-jwk-key
  {:kty "EC"
   :crv "P-256"
   :x "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
   :y "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
   :d "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"})

(deftest ec256-jwk->jca->jwk
  (let [[public private] (load-pair ec256-jwk-key)]
    (is (keys/public-key? public))
    (is (keys/private-key? private))
    (is (= "EC" (.getAlgorithm public)))
    (is (= "EC" (.getAlgorithm private)))
    (is (= ec256-jwk-key (keys/jwk private public)))
    (is (= (dissoc ec256-jwk-key :d) (keys/public-key->jwk public)))))

(deftest ec256-load-sign-verify
  (let [[public private] (load-pair ec256-jwk-key)
        payload "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        signature (dsa/sign payload {:alg :ecdsa+sha256 :key private})
        rfcsig (transcode-to-der
                (b64u "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"))]
    (is (dsa/verify payload signature {:alg :ecdsa+sha256 :key public}))
    (is (dsa/verify payload rfcsig {:alg :ecdsa+sha256 :key public}))))

(deftest ec256-thumbprint
  (is (= "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
         (b64u-str (keys/jwk-thumbprint ec256-jwk-key)))))

(def ec521-jwk-key
  {:kty "EC"
   :crv "P-521"
   :x "AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"
   :y "ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2"
   :d "AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"})

(deftest ec521-jwk-jca-jwk
  (let [[public private] (load-pair ec521-jwk-key)]
    (is (keys/public-key? public))
    (is (keys/private-key? private))
    (is (= ec521-jwk-key (keys/jwk private public)))
    (is (= (dissoc ec521-jwk-key :d) (keys/public-key->jwk public)))
    (doseq [field [:x :y :d]]
      (is (= 66 (alength (b64u (get ec521-jwk-key field))))))))

(deftest ec521-load-sign-verify
  (let [[public private] (load-pair ec521-jwk-key)
        payload "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA"
        signature (dsa/sign payload {:alg :ecdsa+sha512 :key private})
        rfcsig (transcode-to-der
                (b64u "AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"))]
    (is (dsa/verify payload signature {:alg :ecdsa+sha512 :key public}))
    (is (dsa/verify payload rfcsig {:alg :ecdsa+sha512 :key public}))))

(deftest ec521-thumbprint
  (is (= "u5YUSjQ2-2chBi51NSk3t3g7IM4o2KYcnPqPtCNGd3U"
         (b64u-str (keys/jwk-thumbprint ec521-jwk-key)))))

(deftest ec-p384-and-secp256k1-round-trip
  (doseq [[curve coordinate-length signature-algorithm]
          [["secp384r1" 48 :ecdsa+sha384]
           ["secp256k1" 32 :ecdsa+sha256]]]
    (testing curve
      (let [generator (doto (KeyPairGenerator/getInstance "EC")
                        (.initialize (ECGenParameterSpec. curve)))
            pair (.generateKeyPair generator)
            jwk (keys/jwk (.getPrivate pair) (.getPublic pair))
            [public private] (load-pair jwk)
            message "additional JWK curve vector"
            signature (dsa/sign message {:alg signature-algorithm :key private})]
        (is (= (case curve "secp384r1" "P-384" "secp256k1") (:crv jwk)))
        (is (= coordinate-length (alength (b64u (:x jwk)))))
        (is (= coordinate-length (alength (b64u (:y jwk)))))
        (is (= jwk (keys/jwk private public)))
        (is (dsa/verify message signature {:alg signature-algorithm :key public}))))))

(deftest ec-imports-enforce-exact-coordinate-widths
  (let [p384 (let [pair (.generateKeyPair
                          (doto (KeyPairGenerator/getInstance "EC")
                            (.initialize (ECGenParameterSpec. "secp384r1"))))]
               (keys/jwk (.getPrivate pair) (.getPublic pair)))
        secp256k1 (let [pair (.generateKeyPair
                               (doto (KeyPairGenerator/getInstance "EC")
                                 (.initialize (ECGenParameterSpec. "secp256k1"))))]
                    (keys/jwk (.getPrivate pair) (.getPublic pair)))]
    (doseq [[jwk width] [[ec256-jwk-key 32]
                         [p384 48]
                         [ec521-jwk-key 66]
                         [secp256k1 32]]
            field [:x :y]
            importer [keys/jwk->public-key keys/jwk->private-key]]
      (let [coordinate (b64u (get jwk field))
            short-coordinate (if (zero? (aget coordinate 0))
                               (bytes/slice coordinate 1 width)
                               (bytes/slice coordinate 0 (dec width)))
            overlong-coordinate (bytes/concat (byte-array [0]) coordinate)]
        (testing (str (:crv jwk) " " field " short")
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid EC coordinate width"
                                (importer (assoc jwk field (b64u-str short-coordinate))))))
        (testing (str (:crv jwk) " " field " overlong leading zero")
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Invalid EC coordinate width"
                                (importer (assoc jwk field (b64u-str overlong-coordinate))))))))))

(deftest public-private-consistency-is-enforced
  (let [[ec-public _] (load-pair ec256-jwk-key)
        [_ ec-private] (load-pair ec521-jwk-key)
        rsa-public (keys/jwk->public-key rsa-jwk-pubkey)
        [_ rsa-private] (load-pair rsa2048-jwk-key)]
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Public key doesn't match private key"
                          (keys/jwk ec-private ec-public)))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Public key doesn't match private key"
                          (keys/jwk rsa-private rsa-public))))
  (is (thrown? clojure.lang.ExceptionInfo
               (keys/jwk->private-key (assoc ec256-jwk-key :y (:y ec521-jwk-key))))))

(deftest unsupported-jwk-curves-throw
  (is (thrown? Exception (keys/jwk->public-key {:kty "EC" :crv "brainpoolP256r1"
                                                :x "AA" :y "AA"})))
  (is (thrown? Exception (keys/jwk->private-key {:kty "EC" :crv "brainpoolP256r1"
                                                 :x "AA" :y "AA" :d "AA"})))
  (is (thrown? Exception (keys/jwk->public-key {:kty "OKP" :crv "X25519" :x "AA"})))
  (is (thrown? Exception (keys/jwk->private-key {:kty "OKP" :crv "X25519" :x "AA" :d "AA"}))))
