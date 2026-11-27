(ns jolt.crypto.internal.gcm
  "The javax.crypto surface of AES/GCM/NoPadding: GCMParameterSpec and a
  one-shot Cipher over the OpenSSL GCM engine in jolt.crypto.internal.openssl.
  AAD is snapshotted by updateAAD, the 128-bit tag is appended on encryption,
  and decrypted plaintext is returned only after the tag verifies."
  (:require [clojure.string :as str]
            [jolt.crypto.internal.openssl :as openssl]
            [jolt.crypto.internal.support :refer [->ba ba-window concat-bas
                                                  consume-update-args tget
                                                  tput! tt]]))

;; Cipher.ENCRYPT_MODE / DECRYPT_MODE, the JCA's fixed values (jolt.crypto
;; exposes the same two as ENCRYPT-MODE / DECRYPT-MODE).
(def ^:private encrypt-mode 1)
(def ^:private decrypt-mode 2)

(defn cipher
  "A fresh, uninitialized AES/GCM/NoPadding cipher."
  []
  (tt :jolt.crypto/gcm-cipher))

(defn- gcm-parameter-spec [bits iv]
  (when-not (and (integer? bits) (not (neg? bits)) (bytes? iv))
    (throw (ex-info "Invalid GCM parameters" {})))
  (doto (tt :jolt.crypto/gcm-params)
    (tput! :bits bits) (tput! :bytes (aclone iv))))

(defn- init-gcm! [self mode key params]
  (tput! self :mode nil)
  (let [k (->ba key) iv (tget params :bytes)]
    (when-not (and (#{encrypt-mode decrypt-mode} mode)
                   (= :jolt.crypto/gcm-params (tget params :jolt/type))
                   (= 128 (tget params :bits)) (pos? (alength iv))
                   (= "AES" (str/upper-case (.getAlgorithm key)))
                   (#{16 24 32} (alength k)))
      (throw (ex-info "Expected AES key and a 128-bit GCMParameterSpec" {})))
    (when (= mode encrypt-mode)
      (when (and (tget self :last-key) (java.util.Arrays/equals k (tget self :last-key))
                 (java.util.Arrays/equals iv (tget self :last-iv)))
        (throw (ex-info "GCM encryption requires a fresh IV" {})))
      (tput! self :last-key (aclone k))
      (tput! self :last-iv (aclone iv)))
    (tput! self :key (aclone k))
    (tput! self :iv (aclone iv))
    (tput! self :aad [])
    (tput! self :mode mode)
    nil))

(defn- finish-gcm! [self data]
  (let [mode (tget self :mode)]
    (when-not mode (throw (ex-info "GCM cipher requires initialization" {})))
    (let [enc? (= encrypt-mode mode)
          op (if enc? :encrypt :decrypt)
          n (alength data)
          aad (concat-bas (tget self :aad))]
      (tput! self :aad [])
      (when enc? (tput! self :mode nil))
      (when (and (not enc?) (< n 16)) (throw (ex-info "Missing GCM authentication tag" {})))
      (let [ctx (openssl/cipher-context :aes :gcm op (tget self :key) (tget self :iv) {:aad aad})]
        (try
          (if enc?
            (let [body (openssl/cipher-update ctx op data)
                  tag (openssl/gcm-final ctx op nil)]
              (concat-bas [body tag]))
            (let [body (openssl/cipher-update ctx op (ba-window data 0 (- n 16)))]
              (openssl/gcm-final ctx op (ba-window data (- n 16) 16))
              body))
          (finally (openssl/c-cipher-ctx-free ctx)))))))

(defn install!
  "Register GCMParameterSpec and the methods of the AES/GCM/NoPadding cipher."
  []
  (doseq [nm ["GCMParameterSpec" "javax.crypto.spec.GCMParameterSpec"]]
    (__register-class-ctor! nm
      (fn ([bits iv] (gcm-parameter-spec bits iv))
          ([bits iv off len] (gcm-parameter-spec bits (ba-window iv off len))))))
  (__register-class-methods! :jolt.crypto/gcm-params
    {"getTLen" (fn [p] (tget p :bits)) "getIV" (fn [p] (aclone (tget p :bytes)))})
  (__register-class-methods! :jolt.crypto/gcm-cipher
    {"init" init-gcm!
     "getAlgorithm" (fn [_] "AES/GCM/NoPadding")
     "getBlockSize" (fn [_] 16)
     "getIV" (fn [self] (when-let [iv (tget self :iv)] (aclone iv)))
     "updateAAD" (fn [self data & window]
                   (when-not (tget self :mode) (throw (ex-info "GCM cipher requires initialization" {})))
                   (tput! self :aad (conj (tget self :aad) (consume-update-args data window)))
                   nil)
     "doFinal" (fn
                 ([self] (finish-gcm! self (byte-array 0)))
                 ([self data] (finish-gcm! self data))
                 ([self data off len] (finish-gcm! self (ba-window data off len))))}))
