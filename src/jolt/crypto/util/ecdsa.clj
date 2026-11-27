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

(defn- check-output-length [output-length]
  (when-not (and (integer? output-length)
                 (pos? output-length)
                 (even? output-length))
    (invalid)))

(defn- sequence-header
  "[offset length] of a DER SEQUENCE's content: its first INTEGER's offset and
  the length the header declares, in short form or the one-byte long form."
  [data total]
  (when (or (< total 8) (not= 0x30 (unsigned data 0)))
    (invalid))
  (let [first-length (unsigned data 1)]
    (cond
      (= 0x81 first-length)
      (let [sequence-length (unsigned data 2)]
        (when (< sequence-length 128)
          (invalid))
        [3 sequence-length])

      (or (pos? (bit-and first-length 0x80)) (zero? first-length))
      (invalid)

      :else [2 first-length])))

(defn- integer-field
  "[start length] of the canonical DER INTEGER whose tag is at `tag`, which
  must end by `total`."
  [data tag total]
  (when (or (> (+ tag 2) total)
            (not= 0x02 (unsigned data tag)))
    (invalid))
  (let [length (unsigned data (inc tag))
        start (+ tag 2)]
    (when (or (zero? length) (> (+ start length) total))
      (invalid))
    (check-integer data start length)
    [start length]))

(defn- copy-right-aligned!
  "Copy the significant bytes of the integer at [start, start+length) into
  output so that they end at `end`."
  [data [start length] output end]
  (let [significant (significant-length data start length)]
    (System/arraycopy data (- (+ start length) significant)
                      output (- end significant) significant)))

(defn transcode-to-concat
  "Transcode an ASN.1 DER ECDSA signature to fixed-width JWS R+S form."
  [data output-length]
  (let [data (byte-array data)
        total (alength data)
        _ (check-output-length output-length)
        [offset sequence-length] (sequence-header data total)
        _ (when (not= sequence-length (- total offset))
            (invalid))
        r (integer-field data offset total)
        s (integer-field data (apply + r) total)
        _ (when (not= total (apply + s))
            (invalid))
        raw-length (max (significant-length data (first r) (second r))
                        (significant-length data (first s) (second s))
                        (quot output-length 2))
        output (byte-array (* 2 raw-length))]
    (copy-right-aligned! data r output raw-length)
    (copy-right-aligned! data s output (* 2 raw-length))
    output))
