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
;; Modified in 2026 for Jolt: ported the Buddy vectors and added independent
;; RFC, all-digest, counter/feedback/double-pipeline, buffer, and state tests.

(ns jolt.crypto.kdf-test
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.kdf :as kdf])
  (:import java.nio.ByteBuffer))

(def ^:private binary-key
  (codecs/hex->bytes "000102030405060708090a0b0c0d0e0f"))
(def ^:private binary-salt
  (codecs/hex->bytes "f0f1f2f3f4f5f6f7"))

(defn- hex [data]
  (codecs/bytes->hex data))

(defn- derive-bytes [options length]
  (kdf/get-bytes (kdf/engine options) length))

(defn- exception-data [f]
  (try
    (f)
    nil
    (catch Exception e
      (ex-data e))))

(deftest hkdf-sha256-test
  (let [key (codecs/hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt (codecs/hex->bytes "000102030405060708090a0b0c")
        info (codecs/hex->bytes "f0f1f2f3f4f5f6f7f8f9")
        expected (codecs/hex->bytes (str "3cb25f25faacd57a90434f64d0362f2a"
                                         "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                         "34007208d5b887185865"))
        engine (kdf/engine {:key key :salt salt :info info :alg :hkdf+sha256})
        result (kdf/get-bytes engine 42)]
    (is (bytes/equals? result expected))))

(deftest hkdf-rfc5869-empty-salt-and-info-test
  (let [key (codecs/hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        expected (str "8da4e775a563c18f715f802a063c5a31"
                      "b8a11f5c5ee1879ec3454e5f3c738d2d"
                      "9d201395faa4b61a96c8")]
    (is (= expected (hex (derive-bytes {:key key :salt "" :info "" :alg :hkdf+sha256} 42))))
    (is (= expected (hex (derive-bytes {:key key :alg :hkdf :digest :sha256} 42))))))

(deftest hkdf-rfc5869-long-multiblock-test
  (let [key (codecs/hex->bytes (apply str (map #(format "%02x" %) (range 0x50))))
        salt (codecs/hex->bytes (apply str (map #(format "%02x" %) (range 0x60 0xb0))))
        info (codecs/hex->bytes (apply str (map #(format "%02x" %) (range 0xb0 0x100))))
        expected (str "b11e398dc80327a1c8e7f78c596a4934"
                      "4f012eda2d4efad8a050cc4c19afa97c59"
                      "045a99cac7827271cb41c65e590e09da32"
                      "75600c2f09b8367793a9aca3db71cc30c5"
                      "8179ec3e87c14c01d5c1f3434f1d87")]
    (is (= expected (hex (derive-bytes {:key key :salt salt :info info :alg :hkdf+sha256} 82))))))

(deftest kdf1-sha1-test
  (let [key (codecs/hex->bytes "deadbeeffeebdaed")
        engine (kdf/engine {:key key :alg :kdf1 :digest :sha1})
        expected (codecs/hex->bytes (str "B0AD565B14B478CAD4763856FF3016B1A93D840"
                                         "F87261BEDE7DDF0F9305A6E44"))]
    (is (bytes/equals? (kdf/get-bytes engine 32) expected))))

(deftest kdf2-sha1-test
  (let [key (codecs/hex->bytes "deadbeeffeebdaed")
        engine (kdf/engine {:key key :alg :kdf2 :digest :sha1})
        expected (codecs/hex->bytes (str "87261BEDE7DDF0F9305A6E44A74E6A0846DEDE27"
                                         "F48205C6B141888742B0CE2C"))]
    (is (bytes/equals? (kdf/get-bytes engine 32) expected))))

(deftest pbkdf2-sha1-test-1
  (is (= "0c60c80f961f0e71f3a9b524af6012062fe037a6"
         (hex (derive-bytes {:key "password" :salt "salt" :alg :pbkdf2 :digest :sha1
                       :iterations 1} 20)))))

(deftest pbkdf2-sha1-test-2
  (is (= "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
         (hex (derive-bytes {:key "password" :salt "salt" :alg :pbkdf2 :digest :sha1
                       :iterations 2} 20)))))

(deftest pbkdf2-sha1-test-4096
  (is (= "4b007901b765489abead49d926f721d065a429c1"
         (hex (derive-bytes {:key "password" :salt "salt" :alg :pbkdf2 :digest :sha1
                       :iterations 4096} 20)))))

(deftest pbkdf2-sha1-test-16777216
  (let [start (System/nanoTime)
        result (derive-bytes {:key "password" :salt "salt" :alg :pbkdf2 :digest :sha1
                        :iterations 16777216} 20)
        elapsed-ms (/ (- (System/nanoTime) start) 1000000.0)]
    (println (format "PBKDF2-HMAC-SHA1 16777216 iterations: %.3f ms" elapsed-ms))
    (is (= "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984" (hex result)))))

(deftest pbkdf2-sha1-test-long-pass
  (is (= "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
         (hex (derive-bytes {:key "passwordPASSWORDpassword"
                       :salt "saltSALTsaltSALTsaltSALTsaltSALTsalt"
                       :alg :pbkdf2 :digest :sha1 :iterations 4096} 25)))))

(deftest pbkdf2-sha1-test-binary
  (is (= "56fa6aa75548099dcc37d7f03425e0c3"
         (hex (derive-bytes {:key (codecs/str->bytes "pass\000word")
                       :salt (codecs/str->bytes "sa\000lt")
                       :alg :pbkdf2 :digest :sha1 :iterations 4096} 16)))))

(deftest pbkdf2-test-def-iterations
  (let [explicit (derive-bytes {:key "" :salt "" :alg :pbkdf2+sha256 :iterations 1000} 16)
        default (derive-bytes {:key "" :salt "" :alg :pbkdf2+sha256} 16)]
    (is (= 1000 kdf/+pbkdf2-iterations+))
    (is (= "4fc58a21c100ce1835b8f9991d738b56" (hex default)))
    (is (bytes/equals? explicit default))))

(def ^:private generic-known-answers
  [[:hkdf :md5 "c7a2d34700dc068aa9cdf843939526e9930be2ff090a7a37"]
   [:hkdf :sha1 "9a6cb7ee48564bf97976f639cccdeb0bfa08117833327f86"]
   [:hkdf :sha256 "b037f6250f3f4c212bb1f341349ddd36e46caa9ea26a1041"]
   [:hkdf :sha384 "4562364215afacc80738e1c0cf7c859b7267072724cae640"]
   [:hkdf :sha512 "1cfec3752182588cc4b171e1c885d4216726b6c464edc1d9"]
   [:hkdf :sha3-256 "cafca41f0856f08c3b26f8182e55a207f68c12b98b0fd705"]
   [:hkdf :sha3-384 "e3c568d7deacf3aab9471aec80abfece664b961a2a8eb521"]
   [:hkdf :sha3-512 "7a8e78528b3e2a17786fee47178230861518d5be88c63474"]
   [:hkdf :blake2b-512 "05ab46c3a7e4e73cc636537d2c4f3c5bafdef6fd6df8b1fe"]
   [:hkdf :ripemd160 "29ed7d389cd9c858c6f2ae0cc4527c7d81f19478633f30c8"]
   [:kdf1 :md5 "a324b82ec2d58ec64f9cb47e4dff5de883869446e4202156"]
   [:kdf1 :sha1 "c402a87c631246ea7e81b75e541430e840ba4c667bfbee56"]
   [:kdf1 :sha256 "6dff7bb62cec74ccc4418183e72a40c7799697d76f2eaf5c"]
   [:kdf1 :sha384 "befefce290c9f04e980dc827897a800b25ded0a8b289707f"]
   [:kdf1 :sha512 "775d8695d7c9c476eec603f6e080ad18057b58f2901d8d56"]
   [:kdf1 :sha3-256 "16c19358e12b29b65cd4a63dbf23132f2caaa1ae849c6792"]
   [:kdf1 :sha3-384 "aa2ec17a7ff1e40e194592a525b292bb8d06c2be87cc53ed"]
   [:kdf1 :sha3-512 "6f0150fd76adc99315861c7dd71fad62d88b99d96319b61a"]
   [:kdf1 :blake2b-512 "4fb6244a50e3a5db24a4326180d4f6ff4b5568ddcfc2a7f1"]
   [:kdf1 :ripemd160 "15709721bb6255caef3578b105a8a1a4e6d5e00385d68566"]
   [:kdf2 :md5 "83869446e4202156681a18c9eee5c05bce833d0b44ce06f9"]
   [:kdf2 :sha1 "7bfbee563db6962d7393ba98d365fc2a993904e325143c7d"]
   [:kdf2 :sha256 "9905d840e5a0de45c51aa082914f4b87de143a18ab0139e4"]
   [:kdf2 :sha384 "f7e1f0ac752f9f4777be28e5317e3e2d394923cb4d007f14"]
   [:kdf2 :sha512 "39db6bab99cadde02eff062a40bb2e8db52233f6d0a61a27"]
   [:kdf2 :sha3-256 "5096be8e6b6ccceb7df8db6417af34e7980cd9468f5289ee"]
   [:kdf2 :sha3-384 "1e932772270dcb9a66db728102f0ece715dee28d5b7a7b87"]
   [:kdf2 :sha3-512 "b704b687961c923726aeb0c74e7aaf3ed351da39e5cb0322"]
   [:kdf2 :blake2b-512 "e104be4fdd8cf0ab7495c4a0b2a6e33569d305769f1f5058"]
   [:kdf2 :ripemd160 "85d6856610171c3ea9781a83e14a2cde534ecfc23317193a"]
   [:pbkdf2 :md5 "e97e5e4fddb0654ad86778f68d9699102c8b6233bfce623f"]
   [:pbkdf2 :sha1 "5b1231321d6cb1bf83b0eaaf3c425e5488cba8e2332e072d"]
   [:pbkdf2 :sha256 "cbb6ae99392b41ec0b4b90b0a31fa0f0137932caa238f3ba"]
   [:pbkdf2 :sha384 "792b38a97660ca05f1a7c269729934094b6ea665c81580e5"]
   [:pbkdf2 :sha512 "d6504db6967ff225493572662ed66f0bc792a3980feb676f"]
   [:pbkdf2 :sha3-256 "a225da2e7d209b5f39dcda12aa8c5839d0fd8926ca962aca"]
   [:pbkdf2 :sha3-384 "f06a039e5be91c5376104edb57fc669f425b4c58dc28df49"]
   [:pbkdf2 :sha3-512 "e7dc3bbbc506d0eb4366dafcd22cb978fb0248af022c5c91"]
   [:pbkdf2 :blake2b-512 "b7bbcc280c2d40631372b62d60c8d03124b43f9c682d6e2c"]
   [:pbkdf2 :ripemd160 "dd0d6bf8b59364b94ac1e09cddfb43d565c41e136b957951"]])

(deftest generic-kdfs-support-every-digest-test
  (doseq [[algorithm digest expected] generic-known-answers]
    (testing (str algorithm " with " digest)
      (let [options (cond-> {:key binary-key :salt binary-salt :alg algorithm :digest digest}
                      (= algorithm :hkdf) (assoc :info "context")
                      (= algorithm :pbkdf2) (assoc :iterations 2))
            result (derive-bytes options 24)]
        (is (= 24 (count result)))
        (is (= expected (hex result)))))))

(deftest counter-kdf-independent-known-answers-test
  (doseq [[r expected]
          [[32 (str "489181bc4b49c82ae5f67c63e18f2f9210726df455900fb0e43adedc3e8307e6"
                    "e4f86b406fd17d55c92bf6f1d5b244d21210a465f94a0b0d50c304fc30b59d02")]
           [16 (str "6c5c0585b95041b7ce6f6d4645afc1d72d7d28a099973862cde3d40af6d358dd"
                    "ec3b60f49f0fe59a26e32df8ce923d4e973c180d52f005c5ac19358e4db918ae")]]]
    (testing (str "counter width " r)
      (is (= expected (hex (derive-bytes {:key binary-key :salt binary-salt :alg :cmkdf
                                    :digest :sha256 :r r} 64)))))))

(deftest feedback-kdf-independent-known-answers-test
  (doseq [[counter r expected]
          [[true 32 (str "dd1b32f3eb2d9262ac642d537ae0ed0a477ccd57a7e62638f53602ebb660c9"
                         "78db78b51a217a68441fe7e2252adbc00da74db9b5566cee6a13d019b5397669b4")]
           [true 16 (str "882aead5b75f809f65a16b04cfb512c17f21aacc034135932dd7155063606796"
                         "997b1e7b40a7e286838a316874cece95433dc32c57aa3b84e3a8b6931532e09e")]
           [false 32 (str "f018697e5511fca31926528bf65af32bc3cc904a28506578ab5c89ac575bf4eee6"
                          "db388927c573c7cb7dcd0e2c998f1219de5bb271f4bf894d23d2b38c5e80b2")]]]
    (testing (str "counter " counter ", width " r)
      (is (= expected (hex (derive-bytes {:key binary-key :salt binary-salt :alg :fmkdf
                                    :digest :sha256 :counter counter :r r} 64)))))))

(deftest double-pipeline-kdf-independent-known-answers-test
  (doseq [[counter r expected]
          [[true 32 (str "206e64ca683e2f8f515e0e4c2e0bef80818d661bea834ac8e617013a26cdb64b"
                         "8216732db211a4f21f40bb2520e61c6e22efc2039514cb51d8214bb8dbf1f209")]
           [true 16 (str "6fd308f9b693be82d0a1bfab43dc117b4978c027c69755e24e7d2f3bcba6ef7765"
                         "0af69fb67f5f5d8076ff813084a7c16c1eac05e8b11d6b42606ef63e041ddf")]
           [false 32 (str "d5679730c4bb903c24f0b1c6028365c7c3ce6a828a3840dedfa7011d04d51033"
                          "44203ecec16e3c1fa9c25998da27def663ceff083491a2233ccec414abfd1e0d")]]]
    (testing (str "counter " counter ", width " r)
      (is (= expected (hex (derive-bytes {:key binary-key :salt binary-salt :alg :dpimkdf
                                    :digest :sha256 :counter counter :r r} 64)))))))

(deftest named-engine-shorthands-test
  (doseq [algorithm [:hkdf :kdf1 :kdf2 :cmkdf :fmkdf :dpimkdf]
          suffix ["sha256" "sha512" "blake2b-512"]]
    (testing (str algorithm "+" suffix)
      (let [digest (keyword suffix)
            generic {:key "key" :salt "salt" :info "info" :alg algorithm :digest digest}
            named (assoc generic :alg (keyword (str (name algorithm) "+" suffix)))]
        (is (bytes/equals? (derive-bytes generic 24) (derive-bytes named 24))))))
  (doseq [suffix ["sha256" "sha384" "sha512"]]
    (testing (str "pbkdf2+" suffix)
      (let [digest (keyword suffix)
            generic {:key "key" :salt "salt" :alg :pbkdf2 :digest digest}
            named (assoc generic :alg (keyword (str "pbkdf2+" suffix)))]
        (is (bytes/equals? (derive-bytes generic 24) (derive-bytes named 24)))))))

(deftest sha386-compatibility-shorthands-fail-explicitly-test
  (doseq [algorithm [:hkdf :kdf1 :kdf2 :cmkdf :fmkdf :dpimkdf]]
    (testing (str algorithm "+sha386")
      (is (= :sha386 (:algorithm (exception-data
                                  #(kdf/engine {:key "key" :salt "salt"
                                                :alg (keyword (str (name algorithm) "+sha386"))}))))))))

(deftest byte-buffer-contains-derived-bytes-test
  (let [engine (kdf/engine {:key "key" :salt "salt" :info "info" :alg :hkdf+sha256})
        buffer (kdf/get-buffer engine 32)]
    (is (instance? ByteBuffer buffer))
    (is (= 32 (.remaining buffer)))
    (is (= "9ca0d662557439e3b83365f2da4626d35da195c6d9d1779f09838cf9e408966e"
           (hex (.array buffer))))))

(deftest generation-state-matches-buddy-test
  (doseq [[algorithm expected]
          [[:hkdf "9ca0d662557439e3b83365f2da4626d35da195c6d9d1779f09838cf9e408966e"]
           [:kdf1 "eaaeca7517bccfc42293d7278d12aede5fd829614fe6421e67626a8f2ee5703b"]
           [:kdf2 "91b6de3f1999e6dde1cf1f46fe16be3d6475e474450f5a0fa08f76211ea2e5f2"]
           [:cmkdf "86367fe64e7dfb3fe212734901e7d3da357d3dc3a8c05deaaa2192b3d4f5dbdb"]
           [:fmkdf "63be80d0b096ebc5e86d54633027de6a030e9e7fb76207ccf3463895f8325b0c"]
           [:dpimkdf "419097d05245427489ae0e974495dd5d7d07830b0c861f579b0f27676727573a"]]]
    (testing (str algorithm)
      (let [options {:key "key" :salt "salt" :info "info" :alg algorithm :digest :sha256}
            engine (kdf/engine options)
            parts (bytes/concat (kdf/get-bytes engine 7) (kdf/get-bytes engine 25))]
        (is (= (if (#{:kdf1 :kdf2} algorithm)
                 (str (subs expected 0 14) (subs expected 0 50))
                 expected)
               (hex parts)))
        (is (= expected (hex (derive-bytes options 32)))))))
  (doseq [algorithm [:kdf1 :kdf2]]
    (testing (str algorithm " restarts for each request")
      (let [engine (kdf/engine {:key "key" :salt "salt" :alg algorithm :digest :sha256})]
        (is (bytes/equals? (kdf/get-bytes engine 7)
                           (bytes/slice (kdf/get-bytes engine 25) 0 7)))))))

(deftest unsupported-digests-and-invalid-options-fail-explicitly-test
  (doseq [algorithm [:hkdf :kdf1 :kdf2 :cmkdf :fmkdf :dpimkdf :pbkdf2]]
    (testing (str algorithm " unsupported digest")
      (is (= :not-a-digest (:algorithm (exception-data
                                        #(kdf/engine {:key "key" :salt "salt" :alg algorithm
                                                      :digest :not-a-digest})))))))
  (doseq [algorithm [:cmkdf :fmkdf :dpimkdf]]
    (testing (str algorithm " invalid counter width")
      (is (= 12 (:r (exception-data
                     #(kdf/engine {:key "key" :salt "salt" :alg algorithm
                                   :digest :sha256 :r 12})))))))
  (is (= 0 (:iterations (exception-data
                         #(derive-bytes {:key "key" :salt "salt" :alg :pbkdf2
                                   :digest :sha256 :iterations 0} 16))))))

(deftest native-pbkdf2-failure-is-explicit-test
  (with-redefs [openssl/c-pbkdf2-hmac (fn [& _] 0)]
    (is (= :sha256 (:algorithm (exception-data
                                #(openssl/pbkdf2-bytes :sha256 (codecs/str->bytes "key")
                                                       (codecs/str->bytes "salt") 2 16)))))))
