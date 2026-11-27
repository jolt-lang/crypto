;; Copyright 2014-2020 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: removed Apache Commons Codec and Java array-class
;; mechanics, implemented hexadecimal conversion directly, and retained strict
;; java.util.Base64 decoding.

(ns jolt.crypto.codecs
  "Util functions for conversion between strings, bytes, Base64, and hex."
  (:require [jolt.crypto.bytes :as bytes])
  (:import java.nio.ByteBuffer
           java.util.Base64))

(defprotocol IByteArray
  "Facility for converting input parameters to byte arrays."
  (-to-bytes [this] "Represent this as byte array."))

(defn str->bytes
  "Convert string to byte array."
  ([s]
   (str->bytes s "UTF-8"))
  ([s encoding]
   (.getBytes s encoding)))

(defn bytes->str
  "Convert byte array to String."
  ([data]
   (bytes->str data "UTF-8"))
  ([data encoding]
   (String. data encoding)))

(defn bytes->hex
  "Convert a byte array to hex encoded string."
  [data]
  (let [digits "0123456789abcdef"
        output (StringBuilder.)]
    (doseq [b data]
      (let [value (bit-and b 0xff)]
        (.append output (subs digits (bit-shift-right value 4)
                              (inc (bit-shift-right value 4))))
        (.append output (subs digits (bit-and value 0x0f)
                              (inc (bit-and value 0x0f))))))
    (.toString output)))

(defn- hex-digit [c]
  (let [value (int c)]
    (cond
      (<= 48 value 57) (- value 48)
      (<= 65 value 70) (+ 10 (- value 65))
      (<= 97 value 102) (+ 10 (- value 97))
      :else (throw (IllegalArgumentException.
                    (str "Invalid hexadecimal character: " c))))))

(defn hex->bytes
  "Convert hexadecimal encoded string to bytes array."
  [data]
  (let [length (count data)]
    (when (odd? length)
      (throw (IllegalArgumentException. "Hexadecimal input must contain an even number of characters")))
    (let [output (byte-array (/ length 2))]
      (dotimes [i (/ length 2)]
        (let [high (hex-digit (.charAt data (* i 2)))
              low (hex-digit (.charAt data (inc (* i 2))))]
          (aset-byte output i (unchecked-byte (+ (bit-shift-left high 4) low)))))
      output)))

(defn bytes->b64
  "Encode bytes to base64 byte array (using standard variant)."
  {:added "1.8.0"}
  ([data]
   (bytes->b64 data false))
  ([data urlsafe?]
   (let [encoder (if urlsafe?
                   (.withoutPadding (Base64/getUrlEncoder))
                   (Base64/getEncoder))]
     (.encode encoder data))))

(defn bytes->b64-str
  "Encode data to base64 string (using standard variant)."
  {:added "1.11"}
  ([data]
   (-> data bytes->b64 bytes->str))
  ([data urlsafe?]
   (-> data (bytes->b64 urlsafe?) bytes->str)))

(defn- base64-value [value urlsafe?]
  (cond
    (<= 65 value 90) (- value 65)
    (<= 97 value 122) (+ 26 (- value 97))
    (<= 48 value 57) (+ 52 (- value 48))
    (= value (if urlsafe? 45 43)) 62
    (= value (if urlsafe? 95 47)) 63
    :else nil))

(defn- invalid-base64 []
  (throw (IllegalArgumentException. "Invalid Base64 input")))

(defn- validate-base64! [data urlsafe?]
  (let [length (count data)
        padding (loop [i (dec length)
                       padding 0]
                  (if (and (>= i 0)
                           (= 61 (bit-and (aget data i) 0xff)))
                    (recur (dec i) (inc padding))
                    padding))
        content-length (- length padding)
        remainder (mod content-length 4)]
    (dotimes [i length]
      (let [value (bit-and (aget data i) 0xff)]
        (if (= value 61)
          (when (< i content-length)
            (invalid-base64))
          (when (nil? (base64-value value urlsafe?))
            (invalid-base64)))))
    (when (or (> padding 2)
              (and (zero? content-length) (pos? length))
              (not (case remainder
                     0 (zero? padding)
                     2 (or (zero? padding) (= padding 2))
                     3 (or (zero? padding) (= padding 1))
                     false)))
      (invalid-base64))))

(defn b64->bytes
  "Decode base64 bytes array."
  {:added "1.8.0"}
  ([data]
   (b64->bytes data false))
  ([data urlsafe?]
   (let [data (if (bytes/bytes? data) data (-to-bytes data))
         decoder (if urlsafe? (Base64/getUrlDecoder) (Base64/getDecoder))]
     (validate-base64! data urlsafe?)
     (.decode decoder data))))

(defn b64->str
  "Decode base64 byte array to string."
  {:added "1.11"}
  ([data]
   (-> (b64->bytes data false) bytes->str))
  ([data urlsafe?]
   (-> (b64->bytes data urlsafe?) bytes->str)))

(defn long->bytes
  [input]
  (let [buffer (ByteBuffer/allocate 8)]
    (.putLong buffer input)
    (.array buffer)))

(defn bytes->long
  [input]
  (let [buffer (ByteBuffer/allocate 8)]
    (.put buffer input)
    (.flip buffer)
    (.getLong buffer)))

(defn to-bytes
  "Encode as byte array."
  [v]
  (-to-bytes v))

(defn ->bytes
  "A convenience alias for to-bytes."
  {:added "1.11"}
  [data]
  (-to-bytes data))

(extend-protocol IByteArray
  nil
  (-to-bytes [_] (byte-array 0))

  String
  (-to-bytes [data] (str->bytes data))

  Object
  (-to-bytes [data]
    (if (bytes/bytes? data)
      data
      (throw (IllegalArgumentException. "Value cannot be converted to a byte array")))))

(defn b64u->bytes
  "Decode base64 bytes array (using url-safe variant).

  NOTE: DEPRECATED"
  {:added "1.8"
   :deprecated "1.11"}
  [data]
  (b64->bytes data true))

(defn bytes->b64u
  "Encode data to base64 byte array (using url-safe variant).

  NOTE: DEPRECATED"
  {:added "1.8"
   :deprecated "1.11"}
  [data]
  (bytes->b64 data true))
