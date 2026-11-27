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
;; Modified in 2026 for Jolt: replaced Bouncy Castle holders and verifiers with
;; existing X509Certificate values and OpenSSL signature verification.

(ns jolt.crypto.certificates
  "X.509 certificate parsing, inspection, validity, and signature verification."
  (:require [clojure.java.io :as io]
            [jolt.crypto :as crypto])
  (:import [java.io Reader StringReader]
           [java.security.cert CertificateFactory CertificateException X509Certificate]))

(defn- parse-certificate [input]
  (.generateCertificate (CertificateFactory/getInstance "X.509") input))

(defn certificate
  "Read a certificate from a PEM/DER path, byte array, stream, or PEM reader."
  [x]
  (cond
    (bytes? x)
    (parse-certificate x)

    (instance? Reader x)
    (with-open [reader (io/reader x)]
      (parse-certificate (.getBytes (slurp reader) "UTF-8")))

    :else
    (with-open [stream (io/input-stream x)]
      (parse-certificate stream))))

(defn str->certificate
  "Certificate constructor from a PEM string."
  [certdata]
  (with-open [reader (StringReader. ^String certdata)]
    (certificate reader)))

(defn certificate?
  "Return true if object is an X.509 certificate."
  [x]
  (instance? X509Certificate x))

(defn subject
  "Return the subject in certificate RDN order."
  [cert]
  (crypto/certificate-subject cert))

(defn not-before
  "Return the first date this certificate is valid."
  [cert]
  (.getNotBefore cert))

(defn not-after
  "Return the last date this certificate is valid."
  [cert]
  (.getNotAfter cert))

(defn valid-on-date?
  "Return true when the certificate is valid on date, defaulting to now."
  ([cert]
   (valid-on-date? cert (java.util.Date.)))
  ([cert date]
   (try
     (.checkValidity cert date)
     true
     (catch CertificateException _
       false))))

(defn verify-signature
  "Verify that cert is signed with a public key or issuer certificate."
  [cert public-key]
  (crypto/verify-certificate-signature cert public-key))
