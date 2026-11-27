;; Copyright (c) 2018 Andrey Antukh <niwi@niwi.nz>
;; Copyright 2012-2016 Connect2id Ltd.
;;
;; Licensed under the Apache License, Version 2.0 (the "License"); you may not use
;; this file except in compliance with the License. You may obtain a copy of the
;; License at
;;
;;    http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software distributed
;; under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
;; CONDITIONS OF ANY KIND, either express or implied. See the License for the
;; specific language governing permissions and limitations under the License.
;;
;; Modified in 2026 for Jolt: ported the Nimbus transcoding from buddy.util.ECDSA
;; to Clojure and added strict input and DER boundary validation.

(ns jolt.crypto.util.ecdsa
  "ECDSA ASN.1/DER and JWS concatenated R+S signature transcoding.

  The conversion algorithm is derived from nimbus-jose-jwt's ECDSA class and
  from org.apache.xml.security.algorithms.implementations.SignatureECDSA, as
  included in Buddy Core.")

(defn- invalid []
  (throw (RuntimeException. "Invalid ECDSA signature format")))

(defn- unsigned [data index]
  (bit-and (aget data index) 0xff))

(defn- significant-length [data start length]
  (loop [remaining length]
    (if (and (pos? remaining)
             (zero? (aget data (+ start (- length remaining)))))
      (recur (dec remaining))
      remaining)))

(defn- check-integer [data start length]
  (when (or (zero? length)
            (neg? (aget data start))
            (and (> length 1)
                 (zero? (aget data start))
                 (zero? (bit-and (unsigned data (inc start)) 0x80))))
    (invalid))
  (when (zero? (significant-length data start length))
    (invalid)))

(defn transcode-to-der
  "Transcode a JWS concatenated R+S signature to canonical ASN.1 DER."
  [data]
  (let [data (byte-array data)
        total (alength data)]
    (when (or (zero? total) (odd? total))
      (invalid))
    (let [raw-length (quot total 2)
          i (significant-length data 0 raw-length)
          k (significant-length data raw-length raw-length)]
      (when (or (zero? i) (zero? k))
        (invalid))
      (let [r-negative (neg? (aget data (- raw-length i)))
            s-negative (neg? (aget data (- total k)))
            j (+ i (if r-negative 1 0))
            l (+ k (if s-negative 1 0))
            content-length (+ 2 j 2 l)]
        (when (> content-length 255)
          (invalid))
        (let [long-form (>= content-length 128)
              header-length (if long-form 3 2)
              output (byte-array (+ header-length content-length))
              length-offset (if long-form 2 1)]
          (aset-byte output 0 (byte 0x30))
          (when long-form
            (aset-byte output 1 (unchecked-byte 0x81)))
          (aset-byte output length-offset (unchecked-byte content-length))
          (let [r-tag-offset (inc length-offset)]
            (aset-byte output r-tag-offset (byte 0x02))
            (aset-byte output (inc r-tag-offset) (unchecked-byte j))
            (when r-negative
              (aset-byte output (+ r-tag-offset 2) (byte 0)))
            (System/arraycopy data (- raw-length i) output
                              (+ r-tag-offset 2 (- j i)) i)
            (let [s-tag-offset (+ r-tag-offset 2 j)]
              (aset-byte output s-tag-offset (byte 0x02))
              (aset-byte output (inc s-tag-offset) (unchecked-byte l))
              (when s-negative
                (aset-byte output (+ s-tag-offset 2) (byte 0)))
              (System/arraycopy data (- total k) output
                                (+ s-tag-offset 2 (- l k)) k)))
          output)))))

(defn transcode-to-concat
  "Transcode an ASN.1 DER ECDSA signature to fixed-width JWS R+S form."
  [data output-length]
  (let [data (byte-array data)
        total (alength data)]
    (when (or (< total 8)
              (not= 0x30 (unsigned data 0))
              (not (and (integer? output-length)
                        (pos? output-length)
                        (even? output-length))))
      (invalid))
    (let [first-length (unsigned data 1)
          long-form (= 0x81 first-length)
          offset (cond
                   (pos? (bit-and first-length 0x80))
                   (if long-form 3 (invalid))
                   (zero? first-length) (invalid)
                   :else 2)
          sequence-length (if long-form
                            (if (>= total 3) (unsigned data 2) (invalid))
                            first-length)]
      (when (or (and long-form (< sequence-length 128))
                (not= sequence-length (- total offset))
                (< total (+ offset 4))
                (not= 0x02 (unsigned data offset)))
        (invalid))
      (let [r-length (unsigned data (inc offset))
            r-start (+ offset 2)
            s-tag (+ r-start r-length)]
        (when (or (zero? r-length)
                  (> (+ s-tag 2) total)
                  (not= 0x02 (unsigned data s-tag)))
          (invalid))
        (let [s-length (unsigned data (inc s-tag))
              s-start (+ s-tag 2)]
          (when (or (zero? s-length)
                    (not= sequence-length (+ 2 r-length 2 s-length))
                    (not= total (+ s-start s-length)))
            (invalid))
          (check-integer data r-start r-length)
          (check-integer data s-start s-length)
          (let [i (significant-length data r-start r-length)
                j (significant-length data s-start s-length)
                raw-length (max i j (quot output-length 2))
                output (byte-array (* 2 raw-length))]
            (System/arraycopy data (- (+ r-start r-length) i) output (- raw-length i) i)
            (System/arraycopy data (- (+ s-start s-length) j) output (- (* 2 raw-length) j) j)
            output))))))
