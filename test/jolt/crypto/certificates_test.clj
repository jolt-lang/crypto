;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.nz>
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
;; Modified in 2026 for Jolt: replaced Bouncy Castle holder assertions with
;; X509Certificate behavior and added DER, reader, and malformed-input coverage.

(ns jolt.crypto.certificates-test
  (:require [clojure.java.io :as io]
            [clojure.test :refer :all]
            [jolt.crypto.certificates :as certificates]
            [jolt.crypto.keys :as keys])
  (:import [java.security.cert CertificateFactory CertificateException X509Certificate]))

(defn- fixture [name]
  (str "test/_files/" name))

(defn- fixture-text [name]
  (slurp (fixture name)))

(defn- fixture-der [name]
  (with-open [stream (io/input-stream (fixture name))]
    (.getEncoded (.generateCertificate (CertificateFactory/getInstance "X.509") stream))))

(deftest read-certs
  (doseq [cert [(certificates/certificate (fixture "ca-cert.rsa.pem"))
                (certificates/certificate (fixture "cert.rsa.pem"))
                (certificates/str->certificate (fixture-text "cert.rsa.pem"))
                (certificates/certificate (java.io.StringReader. (fixture-text "cert.rsa.pem")))
                (with-open [reader (io/reader (fixture "cert.rsa.pem"))]
                  (certificates/certificate reader))]]
    (is (certificates/certificate? cert))
    (is (instance? X509Certificate cert))))

(deftest read-der-certs-from-bytes-streams-and-paths
  (let [der (fixture-der "cert.rsa.pem")
        expected (certificates/str->certificate (fixture-text "cert.rsa.pem"))
        path (str (System/getProperty "java.io.tmpdir")
                  "/jolt-crypto-certificate-" (System/nanoTime) ".der")]
    (try
      (with-open [out (io/output-stream path)]
        (.write out der))
      (doseq [cert [(certificates/certificate der)
                    (with-open [stream (io/input-stream der)]
                      (certificates/certificate stream))
                    (certificates/certificate path)]]
        (is (certificates/certificate? cert))
        (is (= expected cert)))
      (finally
        (io/delete-file path true)))))

(deftest certificate-predicate-rejects-other-values
  (doseq [value [nil "certificate" {} [] (byte-array 0) 42
                 (keys/public-key (fixture "ca-cert.rsa.pem"))]]
    (is (false? (certificates/certificate? value)))))

(deftest verify-signature
  (let [cert (certificates/certificate (fixture "cert.rsa.pem"))
        ca-cert (certificates/certificate (fixture "ca-cert.rsa.pem"))]
    (testing "cert is signed by ca"
      (is (true? (certificates/verify-signature
                  cert (keys/public-key (fixture "ca-cert.rsa.pem"))))))
    (testing "cert is signed by ca with certificate"
      (is (true? (certificates/verify-signature cert ca-cert))))
    (testing "cert is not self signed"
      (is (false? (certificates/verify-signature
                   cert (keys/public-key (fixture "cert.rsa.pem"))))))
    (testing "cert is not self signed by certificate"
      (is (false? (certificates/verify-signature cert cert))))))

(deftest verification-rejects-malformed-argument-types
  (let [cert (certificates/certificate (fixture "cert.rsa.pem"))
        ca-key (keys/public-key (fixture "ca-cert.rsa.pem"))]
    (is (thrown? clojure.lang.ExceptionInfo
                 (certificates/verify-signature nil ca-key)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (certificates/verify-signature cert nil)))
    (is (thrown? clojure.lang.ExceptionInfo
                 (certificates/verify-signature
                  cert (keys/private-key (fixture "ca-privkey.rsa.pem")))))))

(deftest date-handling
  (let [expired (certificates/certificate (fixture "expired-rsa.crt"))]
    (is (= #inst "2016-12-01T16:18:40.000-00:00" (certificates/not-before expired)))
    (is (= #inst "2016-12-02T16:18:40.000-00:00" (certificates/not-after expired)))
    (is (false? (certificates/valid-on-date? expired)))
    (is (true? (certificates/valid-on-date? expired #inst "2016-12-01T16:18:40.000-00:00")))
    (is (true? (certificates/valid-on-date? expired #inst "2016-12-02T16:18:40.000-00:00")))
    (is (true? (certificates/valid-on-date? expired #inst "2016-12-02T16:17:40.000-00:00")))
    (is (false? (certificates/valid-on-date? expired #inst "2016-12-01T16:18:39.999-00:00")))
    (is (false? (certificates/valid-on-date? expired #inst "2016-12-01T16:17:40.000-00:00")))
    (is (false? (certificates/valid-on-date? expired #inst "2016-12-02T16:18:40.001-00:00")))
    (is (false? (certificates/valid-on-date? expired #inst "2016-12-03T16:17:40.000-00:00")))))

(deftest subject
  (is (= "C=AU,ST=Some-State,O=Internet Widgits Pty Ltd"
         (certificates/subject (certificates/certificate (fixture "cert.rsa.pem"))))))

(deftest malformed-certificates-throw
  (is (thrown? CertificateException (certificates/str->certificate "not a certificate")))
  (is (thrown? CertificateException (certificates/str->certificate "")))
  (is (thrown? CertificateException (certificates/certificate (byte-array [1 2 3 4])))))
