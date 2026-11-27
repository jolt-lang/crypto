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
;; Modified in 2026 for Jolt: ported the Buddy DSA cases to OpenSSL-backed
;; tagged keys and added digest, input-type, known-answer, failure, and
;; native-lifecycle coverage.

(ns jolt.crypto.dsa-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.dsa :as dsa]
            [jolt.crypto.internal.libcrypto :as lc]
            [jolt.crypto.keys :as keys])
  (:import [java.io ByteArrayInputStream]
           [java.security KeyFactory KeyPairGenerator Signature]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]))

(defn- fixture [name]
  (str "test/_files/" name))

(def ^:private keypairs
  {:rsa {:private (keys/private-key (fixture "privkey.3des.rsa.pem") "secret")
         :public (keys/public-key (fixture "pubkey.3des.rsa.pem"))}
   :ec {:private (keys/private-key (fixture "privkey.ecdsa.pem") "secret")
        :public (keys/public-key (fixture "pubkey.ecdsa.pem"))}
   :ed25519 {:private (keys/private-key (fixture "privkey.ed25519.pem"))
             :public (keys/public-key (fixture "pubkey.ed25519.pem"))}
   :ed448 {:private (keys/private-key (fixture "privkey.ed448.pem"))
           :public (keys/public-key (fixture "pubkey.ed448.pem"))}})

(def ^:private algorithm-cases
  (concat
   (for [digest [:sha256 :sha384 :sha512]]
     {:label (str "RSA PKCS#1 " digest)
      :alg (keyword (str "rsassa-pkcs15+" (name digest))) :kind :rsa})
   (for [digest [:sha256 :sha384 :sha512]]
     {:label (str "RSA-PSS " digest)
      :alg (keyword (str "rsassa-pss+" (name digest))) :kind :rsa})
   (for [digest [:sha256 :sha384 :sha512]]
     {:label (str "ECDSA " digest)
      :alg (keyword (str "ecdsa+" (name digest))) :kind :ec})
   [{:label "Ed25519" :alg :eddsa :kind :ed25519}
    {:label "Ed448" :alg :eddsa :kind :ed448}]))

(defn- input-cases []
  (let [path (fixture "pubkey.ecdsa.pem")
        text (slurp path)
        data (.getBytes text "UTF-8")
        file (io/file path)
        uri (.toURI file)]
    [["byte array" #(aclone data)]
     ["string" (fn [] text)]
     ["input stream" #(ByteArrayInputStream. data)]
     ["file" (fn [] file)]
     ["URL" #(.toURL uri)]
     ["URI" (fn [] uri)]]))

(defn- sign-options [{:keys [alg kind]}]
  {:alg alg :key (get-in keypairs [kind :private])})

(defn- verify-options [{:keys [alg kind]}]
  {:alg alg :key (get-in keypairs [kind :public])})

(deftest buddy-input-types-round-trip-every-algorithm
  (doseq [{:keys [label] :as algorithm} algorithm-cases
          [input-label make-input] (input-cases)]
    (testing (str label " over " input-label)
      (let [signature (dsa/sign (make-input) (sign-options algorithm))]
        (is (bytes/bytes? signature))
        (is (true? (dsa/verify (make-input) signature
                               (verify-options algorithm))))))))

(deftest deterministic-and-randomized-signature-semantics
  (let [pkcs {:alg :rsassa-pkcs15+sha256 :kind :rsa}
        pss {:alg :rsassa-pss+sha256 :kind :rsa}
        ecdsa {:alg :ecdsa+sha256 :kind :ec}
        ed25519 {:alg :eddsa :kind :ed25519}
        ed448 {:alg :eddsa :kind :ed448}]
    (is (bytes/equals? (dsa/sign "foobar" (sign-options pkcs))
                       (dsa/sign "foobar" (sign-options pkcs))))
    (doseq [algorithm [pss ecdsa]]
      (is (not (bytes/equals? (dsa/sign "foobar" (sign-options algorithm))
                              (dsa/sign "foobar" (sign-options algorithm))))))
    (doseq [algorithm [ed25519 ed448]]
      (is (bytes/equals? (dsa/sign "foobar" (sign-options algorithm))
                         (dsa/sign "foobar" (sign-options algorithm)))))))

(deftest low-level-offset-updates-sign-the-selected-windows
  (doseq [algorithm [{:alg :rsassa-pss+sha384 :kind :rsa}
                     {:alg :ecdsa+sha512 :kind :ec}
                     {:alg :eddsa :kind :ed448}]]
    (testing (str (:alg algorithm))
      (let [data (codecs/str->bytes "split offset updates")
            padded (bytes/concat (byte-array [9 9 9]) data (byte-array [8 8]))
            engine ((get dsa/+algorithms+ (:alg algorithm)))]
        (dsa/-init engine {:verify false :key (get-in keypairs [(:kind algorithm) :private])})
        (dsa/-update engine padded 3 4)
        (dsa/-update engine padded 7 (- (count data) 4))
        (let [signature (dsa/-end engine nil)]
          (is (true? (dsa/verify data signature (verify-options algorithm)))))))))

(deftest streams-cross-the-internal-buffer-boundary
  (let [data (byte-array (map #(unchecked-byte (mod % 251)) (range 13000)))
        algorithm {:alg :eddsa :kind :ed448}
        signature (dsa/sign (ByteArrayInputStream. data) (sign-options algorithm))]
    (is (true? (dsa/verify (ByteArrayInputStream. data) signature
                           (verify-options algorithm))))))

(deftest host-signature-offset-updates-cover-pss-and-ed448
  (doseq [[kind signature-algorithm]
          [[:rsa "SHA384withRSAandMGF1"]
           [:ed448 "Ed448"]]]
    (testing signature-algorithm
      (let [data (codecs/str->bytes "host offset updates")
            padded (bytes/concat (byte-array [7 7]) data (byte-array [6 6]))
            signer (doto (Signature/getInstance signature-algorithm)
                     (.initSign (get-in keypairs [kind :private]))
                     (.update padded 2 5)
                     (.update padded 7 (- (count data) 5)))
            signature (.sign signer)]
        (is (true? (.verify (doto (Signature/getInstance signature-algorithm)
                              (.initVerify (get-in keypairs [kind :public]))
                              (.update data))
                            signature)))))))

(deftest ed25519-rfc8032-known-answer
  (let [secret "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        public "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        expected (str "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                      "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        factory (KeyFactory/getInstance "Ed25519")
        private-key (.generatePrivate factory
                                      (PKCS8EncodedKeySpec.
                                       (codecs/hex->bytes (str "302e020100300506032b657004220420" secret))))
        public-key (.generatePublic factory
                                    (X509EncodedKeySpec.
                                     (codecs/hex->bytes (str "302a300506032b6570032100" public))))
        message (byte-array 0)]
    (is (= expected (codecs/bytes->hex
                     (dsa/sign message {:alg :eddsa :key private-key}))))
    (is (true? (dsa/verify message (codecs/hex->bytes expected)
                           {:alg :eddsa :key public-key})))))

(deftest fixture-eddsa-openssl-known-answers
  (doseq [[kind message expected-length expected]
          [[:ed25519 "Buddy Ed25519 known answer" 64
            (str "d2de086bd80a14ec62633da1af042ac3cd24870917cee77fa4709b6c0d48c020"
                 "d7a58f5eb1ef09caa8b5395d07b4eb6e9633aa3f29f60051492734f89481b103")]
           [:ed448 "Buddy Ed448 known answer" 114
            (str "1974011f5e74cef9228edb71ccbcc8bcaeab93970888f4f3b2a286780f21c74544"
                 "c9998b6daed4e341e9df683b4dcfbff50fe02de214565980d1b052cff4b45879"
                 "a4ccc096c66bd30b89546752b293645a545067a159c3d6c529e80556df1e99a000"
                 "9454e167435a52c90960f4ce828e2400")]]]
    (testing (name kind)
      (let [algorithm {:alg :eddsa :kind kind}
            signature (dsa/sign message (sign-options algorithm))]
        (is (= expected-length (count signature)))
        (is (= expected (codecs/bytes->hex signature)))
        (is (true? (dsa/verify message (codecs/hex->bytes expected)
                               (verify-options algorithm))))))))

(deftest rsa-pss-openssl-known-answer-and-explicit-parameters
  (let [algorithm {:alg :rsassa-pss+sha256 :kind :rsa}
        message "Buddy RSA-PSS known answer"
        digest-salt-and-mgf1
        (str "aa4b6bf85a3bf2f0655f4f1fd18bc5b083a19c2f7fa33de1bfdf0a3af7deac9791"
             "6e994954580cbf0506a80e6cb38456795d27edd69aa773c0949f57a0c29101a5b1583"
             "12bc28100f448cf77b42aefc42fca5cbf89af94169082f773c60ece7f0f8d0c10755e"
             "7f3282ee5739a01418d69fbbc8cb466dcbc13b00d19a1126e83ab6fa49119ce481a52"
             "c16f14d4a33db03bbf04883944ccd8f4de13a33d73110bf9d59b18bc9daf6755d6c3f"
             "8e977b334453c0030df118e664cf1a8bdb3fdaa87481a211ab7fda4de9f863787e091"
             "394c7ef2c487812bb96d72e6c76917e71a84ad0899bf70be6d6bcacd479fb652527d1"
             "9617d5357e6f3c4872abff69139bbf9b")
        short-salt
        (str "19a6020266069ed411cb60e38728d06b220fe7e0a46d06a5d8678701f5faf4e1515"
             "249a4893cb972bef25c262bd7408cccef73a8cda0d41a11f27917e4328d1578ad326d"
             "7709ca7b725f1d4ca1fa23ae94a78c329c22a3a2281af4c6f8d52dc7644b8f28d7727"
             "e10f435f2a660a201e81aed4cacf8de9d4a6dd6e1938c8155e0ed8dc81eeb1c598586"
             "34742638ff12c8275d61f5c7fd99d95286c08fb030bbc043ef90190f666895b907e3dce"
             "7096a08b5705f5022f6cf6664edd1e4d5fdaff8607c5d29b6d6435d9254855a18d8bd"
             "af4f328dadb34075cbb96f5bd805c5319ef4eaa70db2c6b9a13806334de8d8448094b8"
             "ab17406789221ace55db46aadd7f")
        sha1-mgf1
        (str "54a3a9d8d9676285acf29c7a9f8ef533edf4351508ddaba0365570c261538f4e4ed9"
             "a378f519ccc85d8dff524922ea9d4fd650e8d6536ed76e697e7c92deb55b5b1408833"
             "16301a1f1fb32c56ea47e323774c08c6cca29060258569f6ba871ca6336e680afb4354"
             "b49bf3bc2e6156b0ac92e820f4f4f260a0982a56f6228f2c2c874363fd54f883bf6eee"
             "37933de57251430d0881ce7bf363b7d52c5d89997415498b9ed9748d57cad531e12a18"
             "f7871db7620a696849b9ba8ba071fb9b461fd986ede5e76b73598c8709fdfc8cb78053"
             "24bafb6ffe7dfd1a1c53250ed8822d181d95a83f397684f09013ace6b6c3c43e992471"
             "b935552f9e98f3a9109bc80ee")]
    (is (true? (dsa/verify message (codecs/hex->bytes digest-salt-and-mgf1)
                           (verify-options algorithm))))
    (testing "Bouncy Castle's digest-length salt is required, not auto-detected"
      (is (false? (dsa/verify message (codecs/hex->bytes short-salt)
                              (verify-options algorithm)))))
    (testing "MGF1 uses the message digest, not SHA-1"
      (is (false? (dsa/verify message (codecs/hex->bytes sha1-mgf1)
                              (verify-options algorithm)))))))

(defn- wrong-public-key [kind]
  (case kind
    :rsa (keys/public-key (fixture "pubkey.X509.rsa.pem"))
    :ec (.getPublic (.generateKeyPair (KeyPairGenerator/getInstance "EC")))
    :ed25519 (.getPublic (.generateKeyPair (KeyPairGenerator/getInstance "Ed25519")))
    :ed448 (get-in keypairs [:ed25519 :public])))

(deftest wrong-keys-tampering-and-malformed-signatures-return-false
  (doseq [{:keys [label kind] :as algorithm} algorithm-cases]
    (testing label
      (let [signature (dsa/sign "ordinary invalid signature handling"
                                (sign-options algorithm))
            tampered (aclone signature)]
        (aset-byte tampered 0 (unchecked-byte (bit-xor (aget tampered 0) 1)))
        (is (false? (dsa/verify "ordinary invalid signature handling" tampered
                                (verify-options algorithm))))
        (is (false? (dsa/verify "ordinary invalid signature handling"
                                (byte-array [0 1 2 3])
                                (verify-options algorithm))))
        (is (false? (dsa/verify "ordinary invalid signature handling" signature
                                {:alg (:alg algorithm) :key (wrong-public-key kind)})))))))

(defn- exception-data [f]
  (try (f) nil (catch clojure.lang.ExceptionInfo e (ex-data e))))

(deftest mismatched-key-algorithms-fail-clearly
  (doseq [[algorithm wrong-kind expected actual]
          [[:rsassa-pkcs15+sha256 :ec "RSA" "EC"]
           [:rsassa-pss+sha512 :ec "RSA" "EC"]
           [:ecdsa+sha256 :rsa "EC" "RSA"]
           [:eddsa :rsa "EdDSA" "RSA"]]]
    (testing (str algorithm " rejects " actual)
      (is (= {:expected expected :actual actual}
             (select-keys
              (exception-data #(dsa/sign "mismatch" {:alg algorithm
                                                     :key (get-in keypairs [wrong-kind :private])}))
              [:expected :actual])))
      (is (= {:expected expected :actual actual}
             (select-keys
              (exception-data #(dsa/verify "mismatch" (byte-array 8)
                                           {:alg algorithm
                                            :key (get-in keypairs [wrong-kind :public])}))
              [:expected :actual])))))
  (testing "concrete EdDSA algorithm names reject the other curve"
    (is (= {:expected "Ed448" :actual "Ed25519"}
           (select-keys
            (exception-data
             #(.sign (doto (Signature/getInstance "Ed448")
                       (.initSign (get-in keypairs [:ed25519 :private]))
                       (.update (codecs/str->bytes "mismatch")))))
            [:expected :actual])))
    (is (= {:expected "Ed25519" :actual "Ed448"}
           (select-keys
            (exception-data
             #(.sign (doto (Signature/getInstance "Ed25519")
                       (.initSign (get-in keypairs [:ed448 :private]))
                       (.update (codecs/str->bytes "mismatch")))))
            [:expected :actual])))))

(deftest unknown-algorithms-fail-explicitly
  (is (= :not-a-signature
         (:algorithm (exception-data
                      #(dsa/sign "data" {:alg :not-a-signature
                                         :key (get-in keypairs [:rsa :private])}))))))

(deftest pss-native-contexts-are-freed-on-signing-failure
  (let [md-frees (atom 0)
        pkey-frees (atom 0)
        original-md-free lc/c-md-ctx-free
        original-pkey-free lc/c-pkey-free]
    (with-redefs [lc/c-dgst-sign (fn [& _] 0)
                  lc/c-md-ctx-free (fn [ctx]
                                         (swap! md-frees inc)
                                         (original-md-free ctx))
                  lc/c-pkey-free (fn [pkey]
                                       (swap! pkey-frees inc)
                                       (original-pkey-free pkey))]
      (is (thrown? clojure.lang.ExceptionInfo
                   (dsa/sign "native failure"
                             {:alg :rsassa-pss+sha256
                              :key (get-in keypairs [:rsa :private])}))))
    ;; The MD context also owns the PSS PKEY context created by DigestSignInit.
    (is (= 1 @md-frees))
    (is (= 1 @pkey-frees))))
