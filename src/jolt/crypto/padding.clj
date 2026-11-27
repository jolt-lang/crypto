;; Copyright (c) 2015-2016 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle padding engines with pure
;; Clojure implementations and defined malformed and empty-input behavior.

(ns jolt.crypto.padding
  "Block padding algorithms."
  (:refer-clojure :exclude [count])
  (:require [jolt.crypto :as crypto]
            [jolt.crypto.bytes :as bytes]))

(defn- pkcs7-add-padding [input offset]
  (let [padsize (- (alength input) offset)]
    (bytes/fill! input (unchecked-byte padsize) :start offset)
    padsize))

(defn- pkcs7-pad-count [input]
  (let [length (alength input)]
    (if (zero? length)
      0
      (let [padsize (bit-and (aget input (dec length)) 0xff)]
        (if (or (zero? padsize) (> padsize length))
          0
          (loop [index 1]
            (cond
              (> index padsize) padsize
              (= padsize (bit-and (aget input (- length index)) 0xff))
              (recur (inc index))
              :else 0)))))))

(defn- tbc-add-padding [input offset]
  (let [padsize (- (alength input) offset)
        code (if (pos? offset)
               (if (zero? (bit-and (aget input (dec offset)) 0x01)) -1 0)
               (if (zero? (bit-and (aget (crypto/random-bytes 1) 0) 0x01)) -1 0))]
    (bytes/fill! input code :start offset)
    padsize))

(defn- trailing-byte-count [input code]
  (let [length (alength input)]
    (loop [size 0]
      (if (and (< size length)
               (= code (aget input (- length size 1))))
        (recur (inc size))
        size))))

(defn- tbc-pad-count [input]
  (if (zero? (alength input))
    0
    (let [code (aget input (dec (alength input)))]
      (if (or (zero? code) (= -1 code))
        (trailing-byte-count input code)
        0))))

(defn- zerobyte-add-padding [input offset]
  (let [padsize (- (alength input) offset)]
    (bytes/fill! input 0 :start offset)
    padsize))

(defn- zerobyte-pad-count [input]
  (trailing-byte-count input 0))

(defn padding-engine
  "Create a padding engine for the given algorithm name."
  [alg]
  (condp = alg
    :pkcs7 {:add-padding pkcs7-add-padding
            :pad-count pkcs7-pad-count}
    :tbc {:add-padding tbc-add-padding
          :pad-count tbc-pad-count}
    :zerobyte {:add-padding zerobyte-add-padding
               :pad-count zerobyte-pad-count}
    nil))

(defn- require-engine [alg]
  (or (padding-engine alg)
      (throw (ex-info (str "Unsupported padding algorithm: " alg)
                      {:algorithm alg}))))

(defn pad!
  "Add padding using one of supported padding algorithms."
  ([input offset]
   (pad! input offset :pkcs7))
  ([input offset alg]
   ((:add-padding (require-engine alg)) input offset)))

(defn pad
  "Add padding using one of supported padding algorithms.
  This is a side effect free version of pad! function."
  ([input offset]
   (pad input offset :pkcs7))
  ([input offset alg]
   (let [input (bytes/copy input)]
     (pad! input offset alg)
     input)))

(defn count
  "Get the padding size found on given byte array.
  Malformed and empty input have a zero padding count."
  ([input]
   (count input :pkcs7))
  ([input alg]
   ((:pad-count (require-engine alg)) input)))

(defn unpad
  "Return a copy of the byte array with its padding removed."
  ([input]
   (unpad input :pkcs7))
  ([input alg]
   (let [padsize (count input alg)
         offset (- (clojure.core/count input) padsize)]
     (bytes/slice input 0 offset))))

(defn padded?
  "Check if given byte array has padding using specified
  padding algorithm. If no one is specified, :pkcs7
  will be used."
  ([input]
   (padded? input :pkcs7))
  ([input alg]
   (pos? (count input alg))))
