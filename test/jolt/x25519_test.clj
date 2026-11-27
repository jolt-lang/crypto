(ns jolt.x25519-test
  (:require [clojure.test :refer [deftest is]])
  (:import [java.security KeyPairGenerator KeyFactory]
           [java.security.spec PKCS8EncodedKeySpec X509EncodedKeySpec]
           [javax.crypto KeyAgreement]))

(defn- unhex [s]
  (byte-array (map #(unchecked-byte (Integer/parseInt (apply str %) 16)) (partition 2 s))))

(deftest rfc7748-agreement
  (let [factory (KeyFactory/getInstance "X25519")
        private (.generatePrivate factory (PKCS8EncodedKeySpec. (unhex (str "302e020100300506032b656e04220420"
                            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))))
        public (.generatePublic factory (X509EncodedKeySpec. (unhex (str "302a300506032b656e032100"
                            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))))
        expected (unhex "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        ka (KeyAgreement/getInstance "X25519")]
    (.init ka private)
    (is (thrown? Exception (.generateSecret ka)))
    (is (thrown? Exception (.doPhase ka public false)))
    (dotimes [_ 2]
      (is (nil? (.doPhase ka public true)))
      (is (= (vec expected) (vec (.generateSecret ka)))))
    (let [low (.generatePublic factory (X509EncodedKeySpec.
                                        (unhex (str "302a300506032b656e032100" (apply str (repeat 64 "0"))))))]
      (is (thrown? Exception (.doPhase ka low true))))
    (let [kpg (KeyPairGenerator/getInstance "X25519")
          a (.generateKeyPair kpg) b (.generateKeyPair kpg)
          agree (fn [priv pub]
                  (.init ka priv)
                  (.doPhase ka pub true)
                  (vec (.generateSecret ka)))]
      (is (= "XDH" (.getAlgorithm (.getPublic a))))
      (is (= (agree (.getPrivate a) (.getPublic b))
             (agree (.getPrivate b) (.getPublic a)))))))
