;; Copyright (c) 2014-2018 Andrey Antukh <niwi@niwi.nz>
;; Copyright (c) 2017-2018 Denis Shilov <sxp@bk.ru>
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle RSA specs with OpenSSL
;; parameters, validated supplied and recovered CRT factors, and hand-built
;; RFC 7638 JSON.

(ns jolt.crypto.keys.jwk.rsa
  "JWK support for RSA keys."
  (:require [jolt.crypto :as crypto]
            [jolt.crypto.codecs :as codecs]
            [jolt.crypto.hash :as hash]
            [jolt.crypto.keys.jwk.proto :as proto]))

(defn- mod-pow [base exponent modulus]
  (loop [result 1 base (mod base modulus) exponent exponent]
    (if (zero? exponent)
      result
      (recur (if (odd? exponent) (mod (* result base) modulus) result)
             (mod (* base base) modulus)
             (quot exponent 2)))))

(defn- gcd [a b]
  (loop [a a b b]
    (if (zero? b) a (recur b (mod a b)))))

(defn- mod-inverse [value modulus]
  (loop [old-r value r modulus old-s 1 s 0]
    (if (zero? r)
      (if (= 1 old-r)
        (mod old-s modulus)
        (throw (ex-info "RSA CRT inverse does not exist" {})))
      (let [quotient (quot old-r r)]
        (recur r (- old-r (* quotient r))
               s (- old-s (* quotient s)))))))

(defn- recover-factor [n r t]
  (loop [g 2]
    (when (> g 100)
      (throw (ex-info "Could not recover RSA factors from n/e/d" {})))
    (let [y (mod-pow g r n)]
      (if (or (= 1 y) (= (dec n) y))
        (recur (inc g))
        (let [factor (loop [j 1 y y]
                       (when (<= j t)
                         (let [x (mod (* y y) n)]
                           (cond
                             (= 1 x) (gcd (dec y) n)
                             (= (dec n) x) nil
                             :else (recur (inc j) x)))))]
          (if (and factor (< 1 factor n))
            factor
            (recur (inc g))))))))

(defn- crt-parameters [n e d]
  (when-not (and (pos? n) (pos? e) (pos? d))
    (throw (ex-info "RSA n, e, and d must be positive" {})))
  (let [k (dec (* d e))]
    (when-not (and (pos? k) (even? k))
      (throw (ex-info "Invalid RSA n/e/d parameters" {})))
    (let [[t r] (loop [t 0 r k]
                  (if (odd? r) [t r] (recur (inc t) (quot r 2))))
          p (recover-factor n r t)
          q (quot n p)]
      (when-not (= n (* p q))
        (throw (ex-info "Invalid recovered RSA factors" {})))
      {:p p :q q
       :dp (mod d (dec p))
       :dq (mod d (dec q))
       :qi (mod-inverse q p)})))

(defn- unsigned-bytes [value]
  (let [length (proto/calc-byte-length value)]
    (codecs/b64->bytes (proto/bigint->b64str length value) true)))

(def ^:private crt-fields [:p :q :dp :dq :qi])

(defn- invalid-crt []
  (throw (ex-info "Invalid RSA CRT parameters" {})))

(defn- supplied-crt-parameters [n e d jwk]
  (let [parameters (into {} (map (fn [field]
                                   [field (proto/b64str->bigint (get jwk field))])
                                 crt-fields))
        {:keys [p q dp dq qi]} parameters]
    (when-not (and (pos? n) (pos? e) (pos? d)
                   (< 1 p) (< 1 q)
                   (= n (* p q))
                   (= dp (mod d (dec p)))
                   (= dq (mod d (dec q)))
                   (pos? qi)
                   (= 1 (mod (* qi q) p)))
      (invalid-crt))
    parameters))

(defn- native-parameters [jwk crt]
  {:n (codecs/b64->bytes (:n jwk) true)
   :e (codecs/b64->bytes (:e jwk) true)
   :d (codecs/b64->bytes (:d jwk) true)
   :p (unsigned-bytes (:p crt))
   :q (unsigned-bytes (:q crt))
   :dp (unsigned-bytes (:dp crt))
   :dq (unsigned-bytes (:dq crt))
   :qi (unsigned-bytes (:qi crt))})

(defmethod proto/jwk->private-key "RSA"
  [jwk]
  (let [n (proto/b64str->bigint (:n jwk))
        e (proto/b64str->bigint (:e jwk))
        d (proto/b64str->bigint (:d jwk))
        supplied (filter #(contains? jwk %) crt-fields)]
    (when-not (or (empty? supplied) (= (count crt-fields) (count supplied)))
      (throw (ex-info "Incomplete RSA CRT parameters"
                      {:supplied (vec supplied)
                       :missing (vec (remove #(contains? jwk %) crt-fields))})))
    (let [direct? (seq supplied)
          ;; Only n/e/d-only keys use bounded recovery. Complete CRT inputs
          ;; bypass it and are validated here and by RSA_check_key.
          crt (if direct?
                (supplied-crt-parameters n e d jwk)
                (crt-parameters n e d))
          key (crypto/rsa-private-from-parameters (native-parameters jwk crt))]
      (when direct?
        (jolt.host/ref-put! key :jwk-crt? true))
      key)))

(defmethod proto/jwk->public-key "RSA"
  [jwk]
  (let [n (proto/b64str->bigint (:n jwk))
        e (proto/b64str->bigint (:e jwk))]
    (when-not (and (pos? n) (pos? e))
      (throw (ex-info "RSA modulus and public exponent must be positive"
                      {:n-positive? (pos? n) :e-positive? (pos? e)})))
    (crypto/rsa-public-from-parameters
     (codecs/b64->bytes (:n jwk) true)
     (codecs/b64->bytes (:e jwk) true))))

(defn- parameters->jwk [{:keys [n e]}]
  (let [n (proto/b64str->bigint (proto/bytes->b64str n))
        e (proto/b64str->bigint (proto/bytes->b64str e))]
    {:kty "RSA"
     :e (proto/bigint->b64str (proto/calc-byte-length e) e)
     :n (proto/bigint->b64str (proto/calc-byte-length n) n)}))

(defmethod proto/public-key->jwk "RSA"
  [public]
  (parameters->jwk (crypto/rsa-public-parameters public)))

(defmethod proto/jwk "RSA"
  [private public]
  (let [private-parameters (crypto/rsa-private-parameters private)
        public-jwk (parameters->jwk (crypto/rsa-public-parameters public))
        private-n (:n private-parameters)
        public-n (proto/b64str->bigint (:n public-jwk))
        private-e (proto/b64str->bigint (proto/bytes->b64str (:e private-parameters)))
        public-e (proto/b64str->bigint (:e public-jwk))
        d (proto/b64str->bigint (proto/bytes->b64str (:d private-parameters)))
        private-n' (proto/b64str->bigint (proto/bytes->b64str private-n))]
    (when-not (and (= private-n' public-n) (= private-e public-e))
      (throw (ex-info "Public key doesn't match private key"
                      {:expected (codecs/bytes->hex private-n)
                       :actual (:n public-jwk)})))
    (let [base-jwk (assoc public-jwk :d (proto/bigint->b64str (proto/calc-byte-length d) d))]
      (if (jolt.host/ref-get private :jwk-crt?)
        (reduce (fn [result field]
                  (let [value (proto/b64str->bigint
                               (proto/bytes->b64str (get private-parameters field)))]
                    (assoc result field
                           (proto/bigint->b64str (proto/calc-byte-length value) value))))
                base-jwk
                crt-fields)
        base-jwk))))

;; https://tools.ietf.org/html/rfc7638#section-3.1
(defmethod proto/thumbprint "RSA"
  [jwk]
  (hash/sha256 (str "{\"e\":\"" (:e jwk)
                    "\",\"kty\":\"" (:kty jwk)
                    "\",\"n\":\"" (:n jwk) "\"}")))
