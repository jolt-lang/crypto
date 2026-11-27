;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: ported the low-level AES and ChaCha cases and the
;; high-level authenticated-encryption schemes to OpenSSL, with independent mode,
;; window, lifecycle, known-answer, and tamper coverage.

(ns jolt.crypto.crypto-test
  (:require [clojure.test :refer [deftest is testing]]
            [jolt.crypto.bytes :as bytes]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.crypto :as crypto]
            [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.nonce :as nonce]
            [jolt.ffi :as ffi]))

(defn- hex [data]
  (codecs/bytes->hex data))

(defn- unhex [data]
  (codecs/hex->bytes data))

(defn- exception-data [f]
  (try
    (f)
    nil
    (catch Exception e
      (ex-data e))))

(defn- params [mode key iv op]
  (cond-> {:key key :op op}
    (not= :ecb mode) (assoc :iv iv)))

(deftest buddy-aes-cbc-known-answer
  (let [engine (crypto/block-cipher :aes :cbc)
        key (byte-array 32)
        iv (byte-array 16)
        plaintext (unhex "000000000000000000000000000000aa")
        expected (unhex "876856626d92356877a284975c27e2e2")]
    (is (identical? engine (crypto/initialize! engine (params :cbc key iv :encrypt))))
    (is (bytes/equals? expected (crypto/process-block! engine plaintext)))
    (crypto/init! engine (params :cbc key iv :decrypt))
    (is (bytes/equals? plaintext (crypto/process-block! engine expected)))))

(deftest aes-mode-known-answers-and-stateful-second-blocks
  (let [key (byte-array (range 16))
        iv (byte-array (range 16))
        plaintext1 (byte-array (range 16))
        plaintext2 (byte-array (range 16 32))]
    (doseq [[mode expected1 expected2]
            [[:ecb "0a940bb5416ef045f1c39458c653ea5a"
              "07feef74e1d5036e900eee118e949293"]
             [:cbc "c6a13b37878f5b826f4f8162a1c8d879"
              "35d9dcdb829fec3352e7bf10b84be4a5"]
             [:ctr "0a9509b6456bf642f9ca9e53ca5ee455"
              "1272fe87720d648182c3e71457b911c3"]
             [:sic "0a9509b6456bf642f9ca9e53ca5ee455"
              "1272fe87720d648182c3e71457b911c3"]
             [:ofb "0a9509b6456bf642f9ca9e53ca5ee455"
              "bef60cb655c2b85cf379a4d74522a87c"]]]
      (testing (str mode)
        (let [engine (crypto/block-cipher :aes mode)]
          (crypto/init! engine (params mode key iv :encrypt))
          (is (= expected1 (hex (crypto/process-block! engine plaintext1))))
          (is (= expected2 (hex (crypto/process-block! engine plaintext2))))
          (crypto/init! engine (params mode key iv :decrypt))
          (is (bytes/equals? plaintext1
                             (crypto/process-block! engine (unhex expected1))))
          (is (bytes/equals? plaintext2
                             (crypto/process-block! engine (unhex expected2)))))))))

(deftest aes-key-length-selects-the-exact-variant
  (doseq [[key-length expected]
          [[16 "c6a13b37878f5b826f4f8162a1c8d879"]
           [24 "916251821c73a522c396d62738019607"]
           [32 "f29000b62a499fd0a9f39a6add2e7780"]]]
    (testing (str key-length " bytes")
      (let [engine (crypto/block-cipher :aes :cbc)]
        (crypto/init! engine {:key (byte-array (range key-length))
                              :iv (byte-array (range 16))
                              :op :encrypt})
        (is (= expected (hex (crypto/process-block! engine (byte-array (range 16))))))))))

(deftest block-processing-honors-input-and-output-offsets
  (doseq [mode [:ecb :cbc :ctr :ofb]]
    (testing (str mode)
      (let [engine (crypto/block-cipher :aes mode)
            input (byte-array (concat (repeat 9 99) (range 16) (repeat 7 88)))
            output (byte-array (repeat 40 42))
            expected (crypto/process-block!
                      (doto (crypto/block-cipher :aes mode)
                        (crypto/init! (params mode (byte-array (range 16))
                                                (byte-array (range 16)) :encrypt)))
                      (byte-array (range 16)))]
        (crypto/init! engine (params mode (byte-array (range 16))
                                       (byte-array (range 16)) :encrypt))
        (is (= 16 (crypto/process-block! engine input 9 output 11)))
        (is (bytes/equals? expected (bytes/slice output 11 27)))
        (is (every? #(= 42 %) (concat (take 11 output) (drop 27 output))))))))

(deftest buddy-chacha-known-answers-and-second-chunk
  (let [engine (crypto/stream-cipher :chacha)
        key (byte-array 32)
        iv (unhex "0011001100110011")
        plaintext1 (unhex "121314")
        plaintext2 (unhex "221122112211")
        expected1 (unhex "0e252d")
        expected2 (unhex "fb2eb0a513f4")]
    (crypto/initialize! engine {:key key :iv iv :op :encrypt})
    (is (bytes/equals? expected1 (crypto/process-bytes! engine plaintext1)))
    (is (bytes/equals? expected2 (crypto/process-bytes! engine plaintext2)))
    (crypto/init! engine {:key key :iv iv :op :decrypt})
    (is (bytes/equals? plaintext1 (crypto/process-bytes! engine expected1)))
    (is (bytes/equals? plaintext2 (crypto/process-bytes! engine expected2)))))

(deftest chacha-original-nonce-vector-and-exact-windows
  (let [expected (unhex (str "f799a38af590e06e8a1955f06806b97a"
                             "6f468fb00217ea84f418b64de447ddde1"
                             "4857658571e6066186be36f2c64394635e"
                             "28c6ade2965c6612f2f6717d51a25"))
        input (byte-array (concat (repeat 5 99) (range 64) (repeat 10 88)))
        output (byte-array (repeat 80 42))
        engine (crypto/stream-cipher :chacha)]
    (crypto/init! engine {:key (byte-array (range 32))
                          :iv (byte-array (range 8))
                          :op :encrypt})
    (is (= 1 (crypto/process-bytes! engine input 5 1 output 7)))
    (is (= 20 (crypto/process-bytes! engine input 6 20 output 8)))
    (is (= 43 (crypto/process-bytes! engine input 26 43 output 28)))
    (is (bytes/equals? expected (bytes/slice output 7 71)))
    (is (every? #(= 42 %) (concat (take 7 output) (drop 71 output))))
    (let [suffix-engine (crypto/stream-cipher :chacha)
          suffix-input (bytes/slice input 0 69)
          suffix-output (byte-array 64)]
      (crypto/init! suffix-engine {:key (byte-array (range 32))
                                   :iv (byte-array (range 8))
                                   :op :encrypt})
      (is (= 64 (crypto/process-bytes! suffix-engine suffix-input 5 suffix-output 0)))
      (is (bytes/equals? expected suffix-output)))))

(deftest empty-stream-input-does-not-advance-state
  (let [engine (crypto/stream-cipher :chacha)]
    (crypto/init! engine {:key (byte-array 32) :iv (unhex "0011001100110011") :op :encrypt})
    (is (= 0 (alength (crypto/process-bytes! engine (byte-array 0)))))
    (is (= "0e252d" (hex (crypto/process-bytes! engine (unhex "121314")))))))

(deftest split-by-blocksize-pads-the-last-block
  (let [blocks (crypto/split-by-blocksize (byte-array (range 35)) 16)]
    (is (= 3 (count blocks)))
    (is (every? #(= 16 (alength %)) blocks))
    (is (bytes/equals? (byte-array (range 16)) (nth blocks 0)))
    (is (bytes/equals? (byte-array (range 16 32)) (nth blocks 1)))
    (is (= [32 33 34 0 0 0 0 0 0 0 0 0 0 0 0 0] (vec (nth blocks 2)))))
  (is (= [] (crypto/split-by-blocksize (byte-array 0) 16)))
  (is (= 1 (count (crypto/split-by-blocksize (byte-array 0) 16 true))))
  (is (= 2 (count (crypto/split-by-blocksize (byte-array 16) 16 true)))))

(deftest sizing-aliases-and-concrete-nonces
  (let [block (crypto/block-cipher :aes :cbc)
        stream (crypto/stream-cipher :chacha)]
    (is (identical? crypto/block-size crypto/get-block-size))
    (is (identical? crypto/output-size crypto/get-output-size))
    (is (identical? crypto/init! crypto/initialize!))
    (is (= 16 (crypto/block-size block)))
    (is (= 16 (crypto/get-block-size block)))
    (is (= 1 (crypto/block-size stream)))
    (is (= 16 (alength (nonce/for-engine block))))
    (is (= 8 (alength (nonce/for-engine stream))))))

(deftest unsupported-algorithms-and-modes-fail-explicitly
  (doseq [algorithm [:twofish :serpent :blowfish]]
    (is (= {:alg algorithm}
           (exception-data #(crypto/block-cipher algorithm :cbc)))))
  (is (= {:mode :unknown}
         (exception-data #(crypto/block-cipher :aes :unknown))))
  (is (= {:alg :twofish}
         (exception-data #(crypto/stream-cipher :twofish)))))

(deftest invalid-key-and-iv-sizes-fail-before-native-use
  (doseq [key-length [0 15 17 31 33]]
    (is (= {:key-length key-length}
           (select-keys
            (exception-data
             #(crypto/init! (crypto/block-cipher :aes :cbc)
                            {:key (byte-array key-length) :iv (byte-array 16)}))
            [:key-length]))))
  (doseq [iv-length [0 8 15 17]]
    (is (= {:iv-length iv-length}
           (select-keys
            (exception-data
             #(crypto/init! (crypto/block-cipher :aes :cbc)
                            {:key (byte-array 16) :iv (byte-array iv-length)}))
            [:iv-length]))))
  (is (= {:mode :ecb}
         (select-keys
          (exception-data
           #(crypto/init! (crypto/block-cipher :aes :ecb)
                          {:key (byte-array 16) :iv (byte-array 16)}))
          [:mode])))
  (doseq [key-length [0 16 24 31 33]]
    (is (= {:key-length key-length}
           (select-keys
            (exception-data
             #(crypto/init! (crypto/stream-cipher :chacha)
                            {:key (byte-array key-length) :iv (byte-array 8)}))
            [:key-length]))))
  (doseq [iv-length [0 12 16]]
    (is (= {:iv-length iv-length}
           (select-keys
            (exception-data
             #(crypto/init! (crypto/stream-cipher :chacha)
                            {:key (byte-array 32) :iv (byte-array iv-length)}))
            [:iv-length])))))

(deftest invalid-process-windows-fail-without-native-output
  (let [engine (crypto/block-cipher :aes :cbc)
        input (byte-array 16)
        output (byte-array 16)]
    (crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)})
    (doseq [inoff [-1 1]]
      (is (= {:offset inoff :length 16 :input-length 16}
             (select-keys
              (exception-data #(crypto/process-block! engine input inoff output 0))
              [:offset :length :input-length]))))
    (doseq [outoff [-1 1]]
      (is (= {:output-offset outoff :output-length 16 :required-length 16}
             (select-keys
              (exception-data #(crypto/process-block! engine input 0 output outoff))
              [:output-offset :output-length :required-length])))))
  (let [engine (crypto/stream-cipher :chacha)]
    (crypto/init! engine {:key (byte-array 32) :iv (byte-array 8)})
    (is (= {:offset 2 :length 3 :input-length 4}
           (select-keys
            (exception-data
             #(crypto/process-bytes! engine (byte-array 4) 2 3 (byte-array 8) 0))
            [:offset :length :input-length])))))

(deftest non-aead-end-finalizes-and-returns-zero
  (let [engine (crypto/block-cipher :aes :cbc)
        output (byte-array [42])]
    (crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)})
    (is (= 0 (crypto/end! engine output 0)))
    (is (= [42] (vec output)))
    (is (= 0 (crypto/end! engine output 0)))))

(deftest native-context-is-freed-on-reinit-and-end
  (let [engine (crypto/block-cipher :aes :cbc)
        original-free openssl/c-cipher-ctx-free
        freed (atom [])]
    (with-redefs [openssl/c-cipher-ctx-free
                  (fn [ptr]
                    (swap! freed conj ptr)
                    (original-free ptr))]
      (crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)})
      (let [holder (:context engine)
            first-context @holder]
        (is (some? first-context))
        (crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)})
        (is (= [first-context] @freed))
        (let [second-context @holder]
          (is (some? second-context))
          (is (= 0 (crypto/end! engine (byte-array 0) 0)))
          (is (= [first-context second-context] @freed))
          (is (nil? @holder))
          (crypto/end! engine (byte-array 0) 0)
          (is (= 2 (count @freed))))))))

(deftest native-context-is-freed-on-initialization-failure
  (let [engine (crypto/block-cipher :aes :cbc)
        original-free openssl/c-cipher-ctx-free
        freed (atom [])]
    (crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)})
    (let [holder (:context engine)
          old-context @holder]
      (with-redefs [openssl/c-encrypt-init (fn [& _] 0)
                    openssl/c-cipher-ctx-free
                    (fn [ptr]
                      (swap! freed conj ptr)
                      (original-free ptr))]
        (is (some? (exception-data
                    #(crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)}))))
        (is (= 2 (count @freed)))
        (is (some #{old-context} @freed))
        (is (nil? @holder))))))

(deftest native-context-is-freed-on-update-and-final-failure
  (let [original-free openssl/c-cipher-ctx-free]
    (testing "update"
      (let [engine (crypto/block-cipher :aes :cbc)
            freed (atom [])]
        (crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)})
        (let [holder (:context engine)
              context @holder]
          (with-redefs [openssl/c-encrypt-update (fn [& _] 0)
                        openssl/c-cipher-ctx-free
                        (fn [ptr]
                          (swap! freed conj ptr)
                          (original-free ptr))]
            (is (some? (exception-data
                        #(crypto/process-block! engine (byte-array 16)))))
            (is (= [context] @freed))
            (is (nil? @holder))))))
    (testing "final"
      (let [engine (crypto/block-cipher :aes :cbc)
            freed (atom [])]
        (crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)})
        (let [holder (:context engine)
              context @holder]
          (with-redefs [openssl/c-encrypt-final (fn [& _] 0)
                        openssl/c-cipher-ctx-free
                        (fn [ptr]
                          (swap! freed conj ptr)
                          (original-free ptr))]
            (is (some? (exception-data #(crypto/end! engine (byte-array 0) 0))))
            (is (= [context] @freed))
            (is (nil? @holder))))))))

(deftest native-context-is-freed-when-input-allocation-fails
  (let [engine (crypto/block-cipher :aes :cbc)
        original-free openssl/c-cipher-ctx-free
        freed (atom [])]
    (with-redefs [ffi/alloc (fn [_] (throw (ex-info "injected allocation failure"
                                                    {:injected :allocation})))
                  openssl/c-cipher-ctx-free
                  (fn [ptr]
                    (swap! freed conj ptr)
                    (original-free ptr))]
      (is (= :allocation
             (:injected
              (exception-data
               #(crypto/init! engine {:key (byte-array 16) :iv (byte-array 16)})))))
      (is (= 1 (count @freed)))
      (is (nil? @(:context engine))))))


(defn- flip-byte [input index]
  (let [copy (bytes/copy input)
        value (bit-and (aget copy index) 0xff)]
    (aset-byte copy index (unchecked-byte (bit-xor value 1)))
    copy))

(def ^:private authentication-error
  {:type :validation :cause :authtag})

(deftest gcm-known-answer-sizing-finalization-and-offsets
  (let [key (unhex "feffe9928665731c6d6a8f9467308308")
        iv (unhex "cafebabefacedbaddecaf888")
        aad (unhex "feedfacedeadbeeffeedfacedeadbeefabaddad2")
        plaintext (unhex (str "d9313225f88406e5a55909c5aff5269a"
                              "86a7a9531534f7da2e4c303d8a318a72"
                              "1c3c0c95956809532fcf0e2449a6b525"
                              "b16aedf5aa0de657ba637b39"))
        expected (unhex (str "42831ec2217774244b7221b784d0d49c"
                             "e3aa212f2c02a4e035c17e2329aca12e"
                             "21d514b25466931c7d8f6a5aac84aa05"
                             "1ba30b396a0aac973d58e0915bc94fbc"
                             "3221a5db94fae95ae7121a47"))
        engine (crypto/block-cipher :aes :gcm)
        encrypted (byte-array (repeat 88 42))]
    (crypto/init! engine {:key key :iv iv :aad aad :tagsize 128 :op :encrypt})
    (is (= 76 (crypto/output-size engine (count plaintext))))
    (is (= 60 (crypto/process-block! engine plaintext 0 encrypted 5)))
    (is (= 16 (crypto/end! engine encrypted 65)))
    (is (bytes/equals? expected (bytes/slice encrypted 5 81)))
    (is (every? #(= 42 %) (concat (take 5 encrypted) (drop 81 encrypted))))

    (crypto/init! engine {:key key :iv iv :aad aad :tagsize 128 :op :decrypt})
    (is (= 60 (crypto/output-size engine (count expected))))
    (let [decrypted (byte-array (repeat 66 42))]
      (is (= 60 (crypto/process-block! engine expected 0 decrypted 3)))
      (is (= 0 (crypto/end! engine decrypted 63)))
      (is (bytes/equals? plaintext (bytes/slice decrypted 3 63)))
      (is (every? #(= 42 %) (concat (take 3 decrypted) (drop 63 decrypted)))))))

(deftest gcm-decryption-buffers-the-trailing-tag-across-updates
  (let [key (byte-array (range 16))
        iv (byte-array (range 12))
        aad (byte-array (range 20))
        plaintext (byte-array (range 48))
        ciphertext (unhex (str "936da5cd621ef15343db6b813aae7e07"
                               "a33708f547f8ebe1fe38eb360859bc73"
                               "a585f9d4d0a591c468dd23cceca4f9bd"
                               "9e84a0e99aea0d392a1893a14827e84f"))
        engine (crypto/block-cipher :aes :gcm)
        output (byte-array 48)]
    (crypto/init! engine {:key key :iv iv :aad aad :op :decrypt})
    (is (= 4 (crypto/process-bytes! engine ciphertext 0 20 output 0)))
    (is (= 44 (crypto/process-bytes! engine ciphertext 20 44 output 4)))
    (is (= 0 (crypto/end! engine output 48)))
    (is (bytes/equals? plaintext output))))

(def ^:private high-level-vectors
  [[:aes128-cbc-hmac-sha256 32 16
    (str "eda330f90eecd16c003e5fb09bcff3584ea46a1ec878c15563dc2f75188d78"
         "e3249614456e7cca48a4a7b07c53789dba7a3f0b20bb1d3d61c1401caea6e2"
         "05adb8422b2d672c45f6003f8db7943e2fe5")]
   [:aes192-cbc-hmac-sha384 48 16
    (str "84e817573c1fa71bd3220c57bffe3c0b7e7e6d3c2aa1a638a191470ed84c"
         "d2fb2c5ceb933830122444cc7e35c594e4fcf3a007df738ddebb2629e6aa28"
         "4caa45f41df7d3ce7dc6bbd24a9ef1bd3f10e69fd0651b2632e957")]
   [:aes256-cbc-hmac-sha512 64 16
    (str "f34744ebcd337f209c19e3ac13d82decc9c358c98b58409c50a0d190143aae"
         "feacd6ed8c52a0d0f8b16c9995d389c5287bb6bfe78f4e8e3ac6e75f24a8c1"
         "387ccc15216c14f3c792581e7d45bbbc84c77b31479f75349599f39517765ec11e0e")]
   [:aes128-gcm 16 12
    (str "936da5cd621ef15343db6b813aae7e07a33708f547f8ebe1fe38eb360859bc"
         "73a585f9d4d0a591c468dd23cceca4f9bd9e84a0e99aea0d392a1893a14827e84f")]
   [:aes192-gcm 24 12
    (str "e6f820989dbccf09d83ad689f3a4d27f1e8e21182cb440a967467123d18b3f"
         "43f755d5523e792b2cdb8e3b4f58bf524776c183701ee991b25e838615eb98e43a")]
   [:aes256-gcm 32 12
    (str "4703d418c1e0c41c85489d80bde4766293c79527e46e496b207eff9e01741e"
         "ad21318cdf8be434bf5c8d55c6a4aa061784f2761007b10501393b26c650516a96")]])

(deftest high-level-known-answers-match-buddy
  (doseq [[algorithm key-length iv-length expected] high-level-vectors]
    (testing (str algorithm)
      (let [key (byte-array (range key-length))
            iv (byte-array (range iv-length))
            aad (byte-array (range 20))
            plaintext (byte-array (range 48))
            encrypted (crypto/encrypt plaintext key iv {:alg algorithm :aad aad})]
        (is (= expected (hex encrypted)))
        (is (bytes/equals? plaintext
                           (crypto/decrypt encrypted key iv
                                           {:algorithm algorithm :aad aad})))))))

(deftest high-level-round-trips-cover-empty-and-every-length-through-99
  (doseq [[algorithm key-length iv-length _] high-level-vectors]
    (testing (str algorithm)
      (let [key (byte-array (range key-length))
            iv (byte-array (range iv-length))]
        (doseq [length (range 100)]
          (let [plaintext (nonce/random-bytes length)
                encrypted (crypto/encrypt plaintext key iv {:algorithm algorithm})]
            (is (bytes/equals? plaintext
                               (crypto/decrypt encrypted key iv {:algorithm algorithm}))
                (str algorithm " length " length))))))))

(deftest authenticated-encryption-rejects-tampering-and-truncation
  (doseq [[algorithm key-length iv-length _] high-level-vectors]
    (testing (str algorithm)
      (let [key (byte-array (range key-length))
            iv (byte-array (range iv-length))
            aad (byte-array (range 20))
            encrypted (crypto/encrypt (byte-array (range 33)) key iv
                                      {:alg algorithm :aad aad})
            variants [[:ciphertext (flip-byte encrypted 0)]
                      [:tag (flip-byte encrypted (dec (count encrypted)))]
                      [:truncated-empty (byte-array 0)]
                      [:truncated-byte (byte-array 1)]
                      [:truncated-tag (bytes/slice encrypted 0 (dec (count encrypted)))]]
            options {:algorithm algorithm :aad aad}]
        (doseq [[label input] variants]
          (is (= authentication-error
                 (exception-data #(crypto/decrypt input key iv options)))
              (str algorithm " " label " returned plaintext or the wrong error")))
        (is (= authentication-error
               (exception-data #(crypto/decrypt encrypted key iv
                                                (assoc options :aad (flip-byte aad 0)))))
            (str algorithm " tampered AAD"))
        (is (= authentication-error
               (exception-data #(crypto/decrypt encrypted key (flip-byte iv 0) options)))
            (str algorithm " tampered IV"))))))

(deftest cbc-hmac-authentication-precedes-cbc-decryption
  (let [key (byte-array (range 32))
        iv (byte-array (range 16))
        encrypted (crypto/encrypt (byte-array (range 32)) key iv)
        original-update openssl/c-decrypt-update
        decrypt-calls (atom 0)]
    (with-redefs [openssl/c-decrypt-update
                  (fn [& args]
                    (swap! decrypt-calls inc)
                    (apply original-update args))]
      (is (= authentication-error
             (exception-data #(crypto/decrypt (flip-byte encrypted 0) key iv)))))
    (is (zero? @decrypt-calls))))

(deftest gcm-finalization-frees-native-context-on-success-and-auth-failure
  (let [original-free openssl/c-cipher-ctx-free
        freed (atom [])
        engine (crypto/block-cipher :aes :gcm)]
    (with-redefs [openssl/c-cipher-ctx-free
                  (fn [ptr]
                    (swap! freed conj ptr)
                    (original-free ptr))]
      (crypto/init! engine {:key (byte-array 16) :iv (byte-array 12) :op :encrypt})
      (let [holder (:context engine)
            first-context @holder]
        (crypto/init! engine {:key (byte-array 16) :iv (byte-array 12) :op :encrypt})
        (let [second-context @holder]
          (is (= 16 (crypto/end! engine (byte-array 16) 0)))
          (is (= [first-context second-context] @freed))
          (is (nil? @holder))))
      (let [encrypted (crypto/encrypt (byte-array 16) (byte-array 16) (byte-array 12)
                                      {:alg :aes128-gcm})]
        (crypto/init! engine {:key (byte-array 16) :iv (byte-array 12) :op :decrypt})
        (let [holder (:context engine)
              context @holder
              output (byte-array 16)]
          (crypto/process-bytes! engine (flip-byte encrypted 0) 0 output 0)
          (is (= authentication-error
                 (exception-data #(crypto/end! engine output 16))))
          (is (= context (last @freed)))
          (is (nil? @holder)))))))

(deftest gcm-invalid-tagsize-frees-an-active-context
  (let [engine (crypto/block-cipher :aes :gcm)
        original-free openssl/c-cipher-ctx-free
        freed (atom [])]
    (crypto/init! engine {:key (byte-array 16) :iv (byte-array 12) :op :encrypt})
    (let [holder (:context engine)
          context @holder]
      (with-redefs [openssl/c-cipher-ctx-free
                    (fn [ptr]
                      (swap! freed conj ptr)
                      (original-free ptr))]
        (is (= {:tagsize 64}
               (exception-data
                #(crypto/init! engine {:key (byte-array 16) :iv (byte-array 12)
                                       :tagsize 64 :op :encrypt}))))
        (is (= [context] @freed))
        (is (nil? @holder))))))

(deftest truncated-high-level-gcm-decrypt-frees-an-active-context
  (let [engine (crypto/block-cipher :aes :gcm)
        original-free openssl/c-cipher-ctx-free
        freed (atom [])]
    (crypto/init! engine {:key (byte-array 16) :iv (byte-array 12) :op :decrypt})
    (let [holder (:context engine)
          context @holder]
      (with-redefs [openssl/c-cipher-ctx-free
                    (fn [ptr]
                      (swap! freed conj ptr)
                      (original-free ptr))]
        (is (= authentication-error
               (exception-data
                #(crypto/decrypt-gcm engine (byte-array 15) (byte-array 16)
                                     (byte-array 12) nil))))
        (is (= [context] @freed))
        (is (nil? @holder))))))

(deftest high-level-gcm-helpers-free-context-on-unexpected-failure
  (doseq [operation [:encrypt :decrypt]]
    (testing (str operation)
      (let [engine (crypto/block-cipher :aes :gcm)
            original-free openssl/c-cipher-ctx-free
            freed (atom [])]
        (crypto/init! engine {:key (byte-array 16) :iv (byte-array 12) :op operation})
        (let [holder (:context engine)
              old-context @holder]
          (with-redefs [crypto/get-output-size
                        (fn [& _]
                          (throw (ex-info "injected sizing failure"
                                          {:injected :sizing})))
                        openssl/c-cipher-ctx-free
                        (fn [ptr]
                          (swap! freed conj ptr)
                          (original-free ptr))]
            (is (= :sizing
                   (:injected
                    (exception-data
                     #(case operation
                        :encrypt (crypto/encrypt-gcm engine (byte-array 16)
                                                     (byte-array 16) (byte-array 12) nil)
                        :decrypt (crypto/decrypt-gcm engine (byte-array 16)
                                                     (byte-array 16) (byte-array 12) nil))))))
            (is (= 2 (count @freed)))
            (is (some #{old-context} @freed))
            (is (nil? @holder))))))))
