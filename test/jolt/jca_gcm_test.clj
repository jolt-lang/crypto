(ns jolt.jca-gcm-test
  (:require [clojure.test :refer [deftest is]])
  (:import [javax.crypto Cipher]
           [javax.crypto.spec GCMParameterSpec SecretKeySpec]))

(deftest gcm-known-answer-and-authentication
  (let [key (SecretKeySpec. (byte-array 16) "AES")
        iv (byte-array 12)
        params (GCMParameterSpec. 128 iv)
        c (Cipher/getInstance "AES/GCM/NoPadding")
        open (fn [aad ciphertext]
               (let [d (Cipher/getInstance "AES/GCM/NoPadding")]
                 (.init d Cipher/DECRYPT_MODE key params)
                 (.updateAAD d (byte-array aad))
                 (.doFinal d ciphertext)))]
    (.init c Cipher/ENCRYPT_MODE key params)
    (is (= "58e2fccefa7e3061367f1d57a4e7455a"
           (apply str (map #(format "%02x" (bit-and % 255)) (.doFinal c)))))
    (is (thrown? Exception (.doFinal c)))
    (is (thrown? Exception (.init c Cipher/ENCRYPT_MODE key params)))
    (let [e (Cipher/getInstance "AES/GCM/NoPadding")]
      (.init e Cipher/ENCRYPT_MODE key params)
      (.updateAAD e (byte-array [1]))
      (.updateAAD e (byte-array [2 3]))
      (let [encrypted (.doFinal e (byte-array [4 5]))]
        (is (= [4 5] (vec (open [1 2 3] encrypted))))
        (is (thrown? Exception (open [1 2 4] encrypted)))
        (aset encrypted 0 (unchecked-byte (bit-xor 1 (aget encrypted 0))))
        (is (thrown? Exception (open [1 2 3] encrypted)))))))
