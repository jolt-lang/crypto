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
;; Modified in 2026 for Jolt: ported the low-level AES-CBC and ChaCha cases to
;; OpenSSL and added independent mode, window, lifecycle, and validation coverage.

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
