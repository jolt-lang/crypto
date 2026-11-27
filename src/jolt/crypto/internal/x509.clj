(ns jolt.crypto.internal.x509
  "X.509 certificates for jolt.crypto: parsing PEM and DER through OpenSSL into
  field maps, and the java.security.cert.CertificateFactory / X509Certificate /
  X500Principal shims over them."
  (:require [clojure.string :as str]
            [jolt.crypto.internal.support :refer [as-ba bio-mem-string
                                                  der-out pkey-type ptr-size
                                                  table? tget tput! tt
                                                  with-mem-bio]]
            [jolt.ffi :as ffi]))

;; X.509 certificates. A certificate is parsed from PEM (PEM_read_bio_X509) or
;; DER (d2i_X509) into an X509 that lives only for the duration of the parse:
;; every field a program can ask for is read out then and stored on the shim
;; object, so nothing native outlives the call and the value travels like data.
;; The names print through X509_NAME_print_ex, which spells RFC 2253 exactly as
;; X500Principal.getName does. Times come out as struct tm (ASN1_TIME_to_tm) and
;; the serial as a BIGNUM hex string; i2d_X509 / i2d_PUBKEY are the DER
;; encodings getEncoded answers with, byte-identical to the JVM's.
(ffi/defcfn c-pem-read-x509    "PEM_read_bio_X509"       [:pointer :pointer :pointer :pointer] :pointer)
(ffi/defcfn c-d2i-x509         "d2i_X509"                [:pointer :pointer :long] :pointer)
(ffi/defcfn c-i2d-x509         "i2d_X509"                [:pointer :pointer] :int)
(ffi/defcfn c-x509-free        "X509_free"               [:pointer] :void)
(ffi/defcfn c-x509-subject     "X509_get_subject_name"   [:pointer] :pointer)
(ffi/defcfn c-x509-issuer      "X509_get_issuer_name"    [:pointer] :pointer)
(ffi/defcfn c-name-print-ex    "X509_NAME_print_ex"      [:pointer :pointer :int :ulong] :int)
(ffi/defcfn c-x509-not-before  "X509_get0_notBefore"     [:pointer] :pointer)
(ffi/defcfn c-x509-not-after   "X509_get0_notAfter"      [:pointer] :pointer)
(ffi/defcfn c-asn1-time-to-tm  "ASN1_TIME_to_tm"         [:pointer :pointer] :int)
(ffi/defcfn c-x509-serial      "X509_get_serialNumber"   [:pointer] :pointer)
(ffi/defcfn c-asn1-int-to-bn   "ASN1_INTEGER_to_BN"      [:pointer :pointer] :pointer)
(ffi/defcfn c-bn-bn2hex        "BN_bn2hex"               [:pointer] :pointer)
(ffi/defcfn c-crypto-free      "CRYPTO_free"             [:pointer :pointer :int] :void)
(ffi/defcfn c-x509-version     "X509_get_version"        [:pointer] :long)
(ffi/defcfn c-x509-sig-nid     "X509_get_signature_nid"  [:pointer] :int)
(ffi/defcfn c-obj-nid2obj      "OBJ_nid2obj"             [:int] :pointer)
(ffi/defcfn c-obj-obj2nid      "OBJ_obj2nid"             [:pointer] :int)
(ffi/defcfn c-obj-obj2txt      "OBJ_obj2txt"             [:pointer :int :pointer :int] :int)
(ffi/defcfn c-obj-nid2sn       "OBJ_nid2sn"              [:int] :pointer)
(ffi/defcfn c-x509-get-pubkey  "X509_get_pubkey"         [:pointer] :pointer)
(ffi/defcfn c-x509-get-spki    "X509_get_X509_PUBKEY"    [:pointer] :pointer)
(ffi/defcfn c-spki-get0-param  "X509_PUBKEY_get0_param"  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-i2d-pubkey       "i2d_PUBKEY"              [:pointer :pointer] :int)
(ffi/defcfn c-pkey-free        "EVP_PKEY_free"           [:pointer] :void)
(ffi/defcfn c-bn-free          "BN_free"                 [:pointer] :void)

;; --- parsing -----------------------------------------------------------------
;; XN_FLAG_RFC2253: what X500Principal.getName() spells — reversed RDN order,
;; comma-separated, short attribute names, RFC 2253 escaping.
(def ^:private xn-flag-rfc2253 0x1110317)

(defn- x509-name-rfc2253 [name]
  (bio-mem-string (fn [bio] (c-name-print-ex bio name 0 xn-flag-rfc2253))))

;; The RFC 1779-flavoured spelling X500Name.toString (getSubjectDN().getName())
;; answers: the same RDNs with ", " between them. Split on the unescaped commas.
(defn split-rdns [s]
  (let [n (count s)]
    (loop [i 0 start 0 acc []]
      (cond (>= i n) (conj acc (subs s start))
            (= \\ (nth s i)) (recur (+ i 2) start acc)
            (= \, (nth s i)) (recur (inc i) (inc i) (conj acc (subs s start i)))
            :else (recur (inc i) start acc)))))
(defn- rfc2253->rfc1779 [s]
  (str/join ", " (split-rdns s)))

(defn- days-from-civil
  "Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
  algorithm)."
  [y m d]
  (let [y (if (<= m 2) (dec y) y)
        era (quot (if (>= y 0) y (- y 399)) 400)
        yoe (- y (* era 400))
        doy (+ (quot (+ (* 153 (+ m (if (> m 2) -3 9))) 2) 5) (dec d))
        doe (+ (* yoe 365) (quot yoe 4) (- (quot yoe 100)) doy)]
    (+ (* era 146097) doe -719468)))

(defn- asn1-time->epoch-ms
  "The instant an ASN1_TIME names, as epoch milliseconds. Read as a struct tm —
  the first six ints are tm_sec .. tm_year on every platform — and folded to a
  day count; ASN1 times are UTC by definition."
  [t]
  (let [tm (ffi/alloc 64)]
    (try
      (when (not= 1 (c-asn1-time-to-tm t tm))
        (throw (ex-info "ASN1_TIME_to_tm failed" {})))
      (let [sec (ffi/read tm :int 0) min (ffi/read tm :int 4) hour (ffi/read tm :int 8)
            mday (ffi/read tm :int 12) mon (ffi/read tm :int 16) year (ffi/read tm :int 20)]
        (* 1000 (+ (* 86400 (days-from-civil (+ 1900 year) (inc mon) mday))
                   (* 3600 hour) (* 60 min) sec)))
      (finally (ffi/free tm)))))

(defn- serial-bigint [x509]
  (let [bn (c-asn1-int-to-bn (c-x509-serial x509) ffi/null)]
    (when (ffi/null? bn) (throw (ex-info "ASN1_INTEGER_to_BN failed" {})))
    (try
      (let [hex (c-bn-bn2hex bn)]
        (try (BigInteger. (ffi/ptr->string hex) 16)
             (finally (c-crypto-free hex ffi/null 0))))
      (finally (c-bn-free bn)))))

(defn- obj-oid
  "An ASN1_OBJECT's dotted OID."
  [obj]
  (let [buf (ffi/alloc 128)]
    (try
      (c-obj-obj2txt buf 128 obj 1)
      (ffi/ptr->string buf)
      (finally (ffi/free buf)))))

;; The JVM's names for the signature algorithms it knows; anything else is
;; reported as its OID, as X509Certificate.getSigAlgName does.
(def ^:private sig-alg-names
  {"1.2.840.10045.4.3.2" "SHA256withECDSA" "1.2.840.10045.4.3.3" "SHA384withECDSA"
   "1.2.840.10045.4.3.4" "SHA512withECDSA" "1.2.840.10045.4.3.1" "SHA224withECDSA"
   "1.2.840.10045.4.1" "SHA1withECDSA"
   "1.2.840.113549.1.1.11" "SHA256withRSA" "1.2.840.113549.1.1.12" "SHA384withRSA"
   "1.2.840.113549.1.1.13" "SHA512withRSA" "1.2.840.113549.1.1.14" "SHA224withRSA"
   "1.2.840.113549.1.1.5" "SHA1withRSA" "1.2.840.113549.1.1.4" "MD5withRSA"
   "1.2.840.113549.1.1.10" "RSASSA-PSS"
   "1.3.101.112" "Ed25519" "1.3.101.113" "Ed448"
   "2.16.840.1.101.3.4.3.2" "SHA256withDSA" "1.2.840.10040.4.3" "SHA1withDSA"})

;; PublicKey.getAlgorithm for a SubjectPublicKeyInfo algorithm's short name
(def ^:private key-alg-names
  {"id-ecPublicKey" "EC" "rsaEncryption" "RSA" "rsassaPss" "RSASSA-PSS"
   "dsaEncryption" "DSA" "ED25519" "EdDSA" "ED448" "EdDSA" "X25519" "XDH" "X448" "XDH"})

(defn- x509-public-key
  "{:algorithm :der} for the certificate's subject public key."
  [x509]
  (let [pkey (c-x509-get-pubkey x509)]
    (when (ffi/null? pkey) (throw (ex-info "X509_get_pubkey failed" {})))
    (try
      (let [holder (ffi/alloc ptr-size)]
        (try
          (ffi/write holder :pointer ffi/null 0)
          (c-spki-get0-param holder ffi/null ffi/null ffi/null (c-x509-get-spki x509))
          (let [alg (ffi/read holder :pointer 0)
                sn (if (ffi/null? alg) "" (ffi/ptr->string (c-obj-nid2sn (c-obj-obj2nid alg))))]
            {:algorithm (get key-alg-names sn sn)
             :key-type (pkey-type pkey)
             :der (der-out c-i2d-pubkey pkey)})
          (finally (ffi/free holder))))
      (finally (c-pkey-free pkey)))))

(defn- x509-fields
  "Everything the shim answers, read off a live X509."
  [x509]
  {:der (der-out c-i2d-x509 x509)
   :subject (x509-name-rfc2253 (c-x509-subject x509))
   :issuer (x509-name-rfc2253 (c-x509-issuer x509))
   :not-before (asn1-time->epoch-ms (c-x509-not-before x509))
   :not-after (asn1-time->epoch-ms (c-x509-not-after x509))
   :serial (serial-bigint x509)
   :version (inc (c-x509-version x509))
   :sig-alg-oid (obj-oid (c-obj-nid2obj (c-x509-sig-nid x509)))
   :public-key (x509-public-key x509)})

(defn- pem? [bytes]
  (let [n (min 64 (alength bytes))]
    (str/includes? (String. bytes 0 n "UTF-8") "-----BEGIN")))

(defn- certificate-exception [msg]
  (jolt.host/throwable "java.security.cert.CertificateException" msg))

(defn parse-x509
  "Parse every certificate in `bytes` — one DER certificate, or a PEM file
  holding any number — into field maps (see x509-fields). Throws
  java.security.cert.CertificateException on input that holds none."
  [bytes]
  (let [bytes (as-ba bytes)
        certs (if (and (pos? (alength bytes)) (pem? bytes))
                (with-mem-bio bytes
                  (fn [bio]
                    (loop [acc []]
                      (let [x (c-pem-read-x509 bio ffi/null ffi/null ffi/null)]
                        (if (ffi/null? x)
                          acc
                          (recur (conj acc (try (x509-fields x) (finally (c-x509-free x))))))))))
                (let [n (alength bytes) buf (ffi/alloc (max 1 n)) holder (ffi/alloc ptr-size)]
                  (try
                    (ffi/write-array buf bytes)
                    (ffi/write holder :pointer buf 0)
                    (let [x (c-d2i-x509 ffi/null holder n)]
                      (if (ffi/null? x)
                        []
                        [(try (x509-fields x) (finally (c-x509-free x)))]))
                    (finally (ffi/free buf) (ffi/free holder)))))]
    (when (empty? certs)
      ;; the JVM's wording for input it finds no certificate in
      (throw (certificate-exception "Could not parse certificate: java.io.IOException: Empty input")))
    certs))

;; --- shim objects ------------------------------------------------------------
(defn x509-cert? [x] (and (table? x) (= :jolt.crypto/x509-cert (tget x :jolt/type))))
(defn- x500-principal? [x] (and (table? x) (= :jolt.crypto/x500-principal (tget x :jolt/type))))
(defn- x500-name? [x] (and (table? x) (= :jolt.crypto/x500-name (tget x :jolt/type))))
(defn- ba= [a b] (and (bytes? a) (bytes? b) (= (seq a) (seq b))))

(defn- make-x509 [fields]
  (let [c (tt :jolt.crypto/x509-cert)]
    (doseq [[k v] fields] (tput! c k v))
    c))
(defn- x500-principal [rfc2253] (doto (tt :jolt.crypto/x500-principal) (tput! :name rfc2253)))

;; The head of the JVM's multi-line dump: version, subject, algorithm, key,
;; validity, issuer, serial.
(defn- x509-cert-string [c]
  (let [oid (tget c :sig-alg-oid)]
    (str "[\n[\n  Version: V" (tget c :version)
         "\n  Subject: " (rfc2253->rfc1779 (tget c :subject))
         "\n  Signature Algorithm: " (get sig-alg-names oid oid) ", OID = " oid
         "\n  Key:  " (:algorithm (tget c :public-key)) " public key"
         "\n  Validity: [From: " (java.util.Date. (tget c :not-before))
         ",\n               To: " (java.util.Date. (tget c :not-after)) "]"
         "\n  Issuer: " (rfc2253->rfc1779 (tget c :issuer))
         "\n  SerialNumber: [" (str/lower-case (.toString (tget c :serial) 16)) "]"
         "\n]\n]")))
(defn- x500-name [rfc2253] (doto (tt :jolt.crypto/x500-name) (tput! :name rfc2253)))

;; generateCertificate takes an InputStream on the JVM; bytes and a PEM string
;; are accepted too, since that is what a program has in hand.
(defn- cert-input-bytes [in]
  (cond (bytes? in) in
        (string? in) (.getBytes ^String in "UTF-8")
        :else (.readAllBytes in)))

(defn- install-certificate-exceptions!
  "Register the java.security.cert exception family in the class graph."
  []
  ;; java.security.cert.CertificateFactory / X509Certificate / X500Principal.
  ;; The exception family is registered into the class graph so a (catch
  ;; java.security.cert.CertificateException …) — or (catch Exception …) —
  ;; around generateCertificate catches what it throws.
  (doseq [[c supers] [["java.security.GeneralSecurityException" ["java.lang.Exception"]]
                      ["java.security.cert.CertificateException" ["java.security.GeneralSecurityException"]]
                      ["java.security.cert.CertificateEncodingException" ["java.security.cert.CertificateException"]]
                      ["java.security.cert.CertificateExpiredException" ["java.security.cert.CertificateException"]]
                      ["java.security.cert.CertificateNotYetValidException" ["java.security.cert.CertificateException"]]
                      ["java.security.cert.CertificateParsingException" ["java.security.cert.CertificateException"]]]]
    (jolt.host/register-class-supers! c supers))
  nil)

(defn- install-certificate-factory!
  "java.security.cert.CertificateFactory: X.509 certificates from PEM or DER."
  []
  (doseq [nm ["CertificateFactory" "java.security.cert.CertificateFactory"]]
    (__register-class-statics! nm
      {"getInstance" (fn [type & _]
                       ;; getType answers the spelling asked for, as the JVM does
                       (when-not (#{"X.509" "X509"} (str type))
                         (throw (certificate-exception (str type " not found"))))
                       (doto (tt :jolt.crypto/cert-factory) (tput! :type (str type))))}))
  (__register-class-methods! :jolt.crypto/cert-factory
    {"getType" (fn [self] (tget self :type))
     "generateCertificate" (fn [self in] (make-x509 (first (parse-x509 (cert-input-bytes in)))))
     "generateCertificates" (fn [self in] (mapv make-x509 (parse-x509 (cert-input-bytes in))))})
  nil)

(defn- install-x509-certificate-class!
  "Make X509Certificate shims instances of their classes, and give them value equality, hashing and printing."
  []
  (__register-instance-check!
    (fn [cn val]
      (when (and (table? val) (= :jolt.crypto/x509-cert (tget val :jolt/type))
                 (#{"java.security.cert.X509Certificate" "X509Certificate"
                    "java.security.cert.Certificate" "Certificate"
                    "java.security.cert.X509Extension" "X509Extension"} cn))
        true)))
  (__register-class! x509-cert?
                     (fn [_] "java.security.cert.X509Certificate")
                     (fn [_] ["java.security.cert.X509Certificate" "java.security.cert.Certificate"
                              "java.security.cert.X509Extension" "java.io.Serializable"]))
  (__register-eq! (fn [a b] (or (x509-cert? a) (x509-cert? b)))
                  (fn [a b] (and (x509-cert? a) (x509-cert? b) (ba= (tget a :der) (tget b :der)))))
  (__register-hash! x509-cert? (fn [c] (hash (seq (tget c :der)))))
  (__register-str! x509-cert? (fn [c] (x509-cert-string c)))
  (__register-pr! x509-cert? (fn [c] (x509-cert-string c)))
  nil)

(defn- install-x509-certificate-methods!
  "java.security.cert.X509Certificate's methods."
  []
  (__register-class-methods! :jolt.crypto/x509-cert
    {"getType" (fn [self] "X.509")
     "getEncoded" (fn [self] (aclone (tget self :der)))
     "getVersion" (fn [self] (tget self :version))
     "getSerialNumber" (fn [self] (tget self :serial))
     "getSubjectX500Principal" (fn [self] (x500-principal (tget self :subject)))
     "getIssuerX500Principal" (fn [self] (x500-principal (tget self :issuer)))
     "getSubjectDN" (fn [self] (x500-name (tget self :subject)))
     "getIssuerDN" (fn [self] (x500-name (tget self :issuer)))
     "getNotBefore" (fn [self] (java.util.Date. (tget self :not-before)))
     "getNotAfter" (fn [self] (java.util.Date. (tget self :not-after)))
     "getSigAlgOID" (fn [self] (tget self :sig-alg-oid))
     "getSigAlgName" (fn [self] (let [oid (tget self :sig-alg-oid)] (get sig-alg-names oid oid)))
     ;; the same PublicKey KeyFactory builds, so it initVerify's a Signature
     "getPublicKey" (fn [self]
                      (let [{:keys [algorithm key-type der]} (tget self :public-key)]
                        (doto (tt :jolt.crypto/public-key)
                          (tput! :bytes der)
                          (tput! :algo algorithm)
                          (tput! :key-type key-type))))
     ;; checkValidity() is now; checkValidity(Date) is that instant
     "checkValidity" (fn [self & [date]]
                       (let [now (if date (.getTime date) (System/currentTimeMillis))
                             not-before (tget self :not-before) not-after (tget self :not-after)]
                         (cond
                           (< now not-before)
                           (throw (jolt.host/throwable "java.security.cert.CertificateNotYetValidException"
                                                       (str "NotBefore: " (java.util.Date. not-before))))
                           (> now not-after)
                           (throw (jolt.host/throwable "java.security.cert.CertificateExpiredException"
                                                       (str "NotAfter: " (java.util.Date. not-after)))))
                         nil))
     "hashCode" (fn [self] (hash (seq (tget self :der))))
     "equals" (fn [self o] (and (x509-cert? o) (ba= (tget self :der) (tget o :der))))
     "toString" (fn [self] (x509-cert-string self))})
  nil)

(defn- install-x500-principal!
  "javax.security.auth.x500.X500Principal, and the java.security.Principal getSubjectDN/getIssuerDN answer."
  []
  ;; javax.security.auth.x500.X500Principal (getName is RFC 2253) and the
  ;; java.security.Principal getSubjectDN/getIssuerDN answer (getName is the
  ;; RFC 1779 spelling X500Name.toString uses).
  (doseq [nm ["X500Principal" "javax.security.auth.x500.X500Principal"]]
    (__register-class-ctor! nm (fn [name & _] (x500-principal (str name)))))
  (__register-instance-check!
    (fn [cn val]
      (when (and (table? val) (#{:jolt.crypto/x500-principal :jolt.crypto/x500-name} (tget val :jolt/type))
                 (or (#{"java.security.Principal" "Principal"} cn)
                     (and (= :jolt.crypto/x500-principal (tget val :jolt/type))
                          (#{"javax.security.auth.x500.X500Principal" "X500Principal"} cn))))
        true)))
  (__register-class! x500-principal?
                     (fn [_] "javax.security.auth.x500.X500Principal")
                     (fn [_] ["javax.security.auth.x500.X500Principal" "java.security.Principal" "java.io.Serializable"]))
  (__register-eq! (fn [a b] (or (x500-principal? a) (x500-principal? b)))
                  (fn [a b] (and (x500-principal? a) (x500-principal? b) (= (tget a :name) (tget b :name)))))
  (__register-hash! x500-principal? (fn [p] (hash (tget p :name))))
  (__register-str! x500-principal? (fn [p] (rfc2253->rfc1779 (tget p :name))))
  (__register-pr! x500-principal? (fn [p] (rfc2253->rfc1779 (tget p :name))))
  (__register-str! x500-name? (fn [p] (rfc2253->rfc1779 (tget p :name))))
  (__register-pr! x500-name? (fn [p] (rfc2253->rfc1779 (tget p :name))))
  (__register-class-methods! :jolt.crypto/x500-principal
    {"getName" (fn [self & [format]]
                 (case (some-> format str str/upper-case)
                   (nil "RFC2253") (tget self :name)
                   "RFC1779" (rfc2253->rfc1779 (tget self :name))
                   "CANONICAL" (str/lower-case (tget self :name))
                   (throw (ex-info (str "invalid format specified: " format) {:format format}))))
     "toString" (fn [self] (rfc2253->rfc1779 (tget self :name)))
     "hashCode" (fn [self] (hash (tget self :name)))
     "equals" (fn [self o] (and (x500-principal? o) (= (tget self :name) (tget o :name))))})
  (__register-class-methods! :jolt.crypto/x500-name
    {"getName" (fn [self] (rfc2253->rfc1779 (tget self :name)))
     "toString" (fn [self] (rfc2253->rfc1779 (tget self :name)))})
  nil)

(defn install!
  "Register the X.509 certificate classes jolt.crypto provides."
  []
  (install-certificate-exceptions!)
  (install-certificate-factory!)
  (install-x509-certificate-class!)
  (install-x509-certificate-methods!)
  (install-x500-principal!))
