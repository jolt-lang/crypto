(ns jolt.crypto.x509-test
  "The certificate builder, checked from the outside: what the JDK-shaped
  X509Certificate answers, and what OpenSSL itself makes of the DER (signature,
  extensions, host and IP matching, chain building). The OpenSSL bindings here
  are test-only and read the certificate the way a TLS peer would."
  (:require [clojure.string :as str]
            [jolt.crypto]
            [jolt.crypto.x509 :as x509]
            [jolt.ffi :as ffi]))

(import '[java.security KeyPairGenerator KeyFactory])
(import '[java.security.spec PKCS8EncodedKeySpec])
(import '[java.security.cert CertificateFactory X509Certificate])

(def ^:private failures (atom 0))
(defn- check [label ok?] (println (if ok? "ok  " "FAIL") label) (when-not ok? (swap! failures inc)))

(defn- ba= [a b] (= (seq a) (seq b)))

;; --- test-only OpenSSL ---------------------------------------------------------
(ffi/defcfn t-d2i-x509        "d2i_X509"                    [:pointer :pointer :long] :pointer)
(ffi/defcfn t-x509-free       "X509_free"                   [:pointer] :void)
(ffi/defcfn t-d2i-pubkey      "d2i_PUBKEY"                  [:pointer :pointer :long] :pointer)
(ffi/defcfn t-pkey-free       "EVP_PKEY_free"               [:pointer] :void)
(ffi/defcfn t-x509-verify     "X509_verify"                 [:pointer :pointer] :int)
(ffi/defcfn t-check-issued    "X509_check_issued"           [:pointer :pointer] :int)
(ffi/defcfn t-check-host      "X509_check_host"             [:pointer :string :size_t :uint :pointer] :int)
(ffi/defcfn t-check-ip        "X509_check_ip_asc"           [:pointer :string :uint] :int)
(ffi/defcfn t-key-usage       "X509_get_key_usage"          [:pointer] :uint)
(ffi/defcfn t-ext-key-usage   "X509_get_extended_key_usage" [:pointer] :uint)
(ffi/defcfn t-ext-flags       "X509_get_extension_flags"    [:pointer] :uint)
(ffi/defcfn t-skid            "X509_get0_subject_key_id"    [:pointer] :pointer)
(ffi/defcfn t-akid            "X509_get0_authority_key_id"  [:pointer] :pointer)
(ffi/defcfn t-octet-cmp       "ASN1_OCTET_STRING_cmp"       [:pointer :pointer] :int)
(ffi/defcfn t-ext-by-nid      "X509_get_ext_by_NID"         [:pointer :int :int] :int)
(ffi/defcfn t-get-ext         "X509_get_ext"                [:pointer :int] :pointer)
(ffi/defcfn t-ext-critical    "X509_EXTENSION_get_critical" [:pointer] :int)
(ffi/defcfn t-store-new       "X509_STORE_new"              [] :pointer)
(ffi/defcfn t-store-free      "X509_STORE_free"             [:pointer] :void)
(ffi/defcfn t-store-add       "X509_STORE_add_cert"         [:pointer :pointer] :int)
(ffi/defcfn t-sctx-new        "X509_STORE_CTX_new"          [] :pointer)
(ffi/defcfn t-sctx-free       "X509_STORE_CTX_free"         [:pointer] :void)
(ffi/defcfn t-sctx-init       "X509_STORE_CTX_init"         [:pointer :pointer :pointer :pointer] :int)
(ffi/defcfn t-verify-cert     "X509_verify_cert"            [:pointer] :int)
(ffi/defcfn t-sctx-error      "X509_STORE_CTX_get_error"    [:pointer] :int)
(ffi/defcfn t-err-clear       "ERR_clear_error"             [] :void)
(ffi/defcfn t-err-peek        "ERR_peek_error"              [] :ulong)

(def ^:private ptr-size (ffi/sizeof :pointer))

(defn- with-d2i [d2i free der f]
  (let [der (if (bytes? der) der (byte-array der)) n (alength der)
        buf (ffi/alloc (max 1 n)) holder (ffi/alloc ptr-size)]
    (try
      (ffi/write-array buf der)
      (ffi/write holder :pointer buf 0)
      (let [obj (d2i ffi/null holder n)]
        (when (ffi/null? obj) (throw (ex-info "test: d2i failed" {})))
        (try (f obj) (finally (free obj))))
      (finally (ffi/free buf) (ffi/free holder)))))

(defn- with-x509 [cert f] (with-d2i t-d2i-x509 t-x509-free (.getEncoded cert) f))
(defn- with-pub [key f] (with-d2i t-d2i-pubkey t-pkey-free (.getEncoded key) f))

(defn- signed-by?
  "OpenSSL's X509_verify of cert's signature against key."
  [cert key]
  (with-x509 cert (fn [x] (with-pub key (fn [k] (let [r (t-x509-verify x k)] (t-err-clear) (= 1 r)))))))

(defn- issued-by?
  "X509_check_issued: names chain, AKID matches, issuer may sign certificates."
  [issuer cert]
  (with-x509 issuer (fn [i] (with-x509 cert (fn [c] (zero? (t-check-issued i c)))))))

(defn- chain-error
  "X509_verify_cert of leaf against a store holding only the anchors: 0 is
  X509_V_OK, anything else the verify error code."
  [anchors leaf]
  (let [store (t-store-new) ctx (t-sctx-new)]
    (try
      (doseq [a anchors] (with-x509 a (fn [x] (t-store-add store x))))
      (with-x509 leaf
        (fn [x]
          (t-sctx-init ctx store x ffi/null)
          (let [ok (t-verify-cert ctx) err (t-sctx-error ctx)]
            (t-err-clear)
            (if (= 1 ok) 0 err))))
      (finally (t-sctx-free ctx) (t-store-free store)))))

(defn- host? [cert h] (with-x509 cert (fn [x] (= 1 (t-check-host x h 0 0 ffi/null)))))
(defn- ip? [cert ip] (with-x509 cert (fn [x] (= 1 (t-check-ip x ip 0)))))
(defn- key-usage [cert] (with-x509 cert t-key-usage))
(defn- ext-key-usage [cert] (with-x509 cert t-ext-key-usage))
(defn- ext-flags [cert] (with-x509 cert t-ext-flags))
(defn- skid? [cert] (with-x509 cert (fn [x] (not (ffi/null? (t-skid x))))))
(defn- akid? [cert] (with-x509 cert (fn [x] (not (ffi/null? (t-akid x))))))
(defn- akid-matches? [issuer cert]
  (with-x509 issuer
    (fn [i] (with-x509 cert
              (fn [c] (let [s (t-skid i) a (t-akid c)]
                        (and (not (ffi/null? s)) (not (ffi/null? a)) (zero? (t-octet-cmp s a)))))))))
(defn- ext-critical
  "nil when the extension is absent, else whether it is marked critical."
  [cert nid]
  (with-x509 cert
    (fn [x] (let [i (t-ext-by-nid x nid -1)]
              (when (>= i 0) (= 1 (t-ext-critical (t-get-ext x i))))))))

(def ^:private nid-basic-constraints 87)
(def ^:private nid-key-usage 83)
(def ^:private nid-subject-alt-name 85)
(def ^:private no-usage 0xffffffff)   ; UINT32_MAX: the extension is absent
(def ^:private exflag-ca 0x10)
(def ^:private exflag-bcons 0x1)

(defn- error-message [thunk]
  (try (thunk) :no-throw (catch Exception e (or (ex-message e) (str e)))))
(defn- rejects? [needle thunk]
  (let [m (error-message thunk)]
    (and (string? m) (str/includes? m needle))))

(def ^:private localhost-san [[:dns "localhost"] [:ip "127.0.0.1"] [:ip "::1"]])
(def ^:private day-ms 86400000)

(defn- keypair [algo]
  (.generateKeyPair (KeyPairGenerator/getInstance algo)))

;; --- tests ---------------------------------------------------------------------
(defn- test-self-signed-ec []
  (let [before (System/currentTimeMillis)
        {:keys [certificate private-key]} (x509/generate {:subject "CN=localhost,O=Example"
                                                          :san localhost-san
                                                          :days 30})
        cert certificate
        nb (.getTime (.getNotBefore cert)) na (.getTime (.getNotAfter cert))]
    (check "generate answers an X509Certificate" (instance? X509Certificate cert))
    (check "generate answers its private key" (= "EC" (.getAlgorithm private-key)))
    (check "the default key is EC" (= "EC" (.getAlgorithm (.getPublicKey cert))))
    (check "version 3" (= 3 (.getVersion cert)))
    (check "subject (RFC 2253)" (= "CN=localhost,O=Example" (.getName (.getSubjectX500Principal cert))))
    (check "self-signed: issuer is the subject" (= "CN=localhost,O=Example" (.getName (.getIssuerX500Principal cert))))
    (check "EC signs SHA256withECDSA" (= "SHA256withECDSA" (.getSigAlgName cert)))
    (check "notBefore is now (to the second)" (<= (- before 1000) nb (+ (System/currentTimeMillis) 1000)))
    (check ":days 30 is exactly 30 days" (= (* 30 day-ms) (- na nb)))
    (check "the default serial is positive and under 2^159"
           (let [s (.getSerialNumber cert)] (and (pos? s) (< s (apply * (repeat 159 2))))))
    (check "two certificates get different serials"
           (not= (.getSerialNumber cert)
                 (.getSerialNumber (:certificate (x509/generate {:subject "CN=localhost"})))))
    (check "OpenSSL verifies the self-signature" (signed-by? cert (.getPublicKey cert)))
    (check "OpenSSL sees it as self-issued" (issued-by? cert cert))
    (check "it is its own trust anchor" (zero? (chain-error [cert] cert)))
    (check "SAN DNS localhost matches" (host? cert "localhost"))
    (check "SAN IP 127.0.0.1 matches" (ip? cert "127.0.0.1"))
    (check "SAN IP ::1 matches" (ip? cert "::1"))
    (check "another host does not match" (not (host? cert "example.com")))
    (check "another IP does not match" (not (ip? cert "10.0.0.1")))
    (check "SAN is not critical" (false? (ext-critical cert nid-subject-alt-name)))
    (check "basicConstraints is present and not critical for a leaf"
           (false? (ext-critical cert nid-basic-constraints)))
    (check "a leaf is not a CA"
           (let [f (ext-flags cert)] (and (pos? (bit-and f exflag-bcons)) (zero? (bit-and f exflag-ca)))))
    (check "subjectKeyIdentifier is present" (skid? cert))
    (check "no authorityKeyIdentifier when self-signed" (not (akid? cert)))
    (check "no keyUsage unless asked" (= no-usage (key-usage cert)))
    (check "no extendedKeyUsage unless asked" (= no-usage (ext-key-usage cert)))
    (check "the private key matches the certificate"
           (ba= (.getEncoded private-key)
                (.getEncoded (.generatePrivate (KeyFactory/getInstance "EC")
                                               (PKCS8EncodedKeySpec. (.getEncoded private-key))))))))

(defn- test-key-types []
  (let [{rsa :certificate rsa-key :private-key} (x509/generate {:subject "CN=localhost" :key-type :rsa
                                                                :san localhost-san})]
    (check "RSA signs SHA256withRSA" (= "SHA256withRSA" (.getSigAlgName rsa)))
    (check "RSA key" (= "RSA" (.getAlgorithm rsa-key)))
    (check "the RSA default is 2048 bits (a 294-byte SPKI)"
           (= 294 (alength (.getEncoded (.getPublicKey rsa)))))
    (check "OpenSSL verifies the RSA self-signature" (signed-by? rsa (.getPublicKey rsa))))
  (let [rsa (:certificate (x509/generate {:subject "CN=x" :key-type :rsa :key-size 3072}))]
    (check ":key-size 3072 makes a 3072-bit key (a 422-byte SPKI)"
           (= 422 (alength (.getEncoded (.getPublicKey rsa))))))
  (let [ec (:certificate (x509/generate {:subject "CN=x" :key-type :ec :key-size 384}))]
    (check ":key-size 384 makes a P-384 key (a 120-byte SPKI)"
           (= 120 (alength (.getEncoded (.getPublicKey ec)))))
    (check "a P-384 key still signs SHA256withECDSA" (= "SHA256withECDSA" (.getSigAlgName ec))))
  (let [ed (:certificate (x509/generate {:subject "CN=localhost" :key-type :ed25519}))]
    (check "Ed25519 signs Ed25519" (= "Ed25519" (.getSigAlgName ed)))
    (check "Ed25519 key" (= "EdDSA" (.getAlgorithm (.getPublicKey ed))))
    (check "OpenSSL verifies the Ed25519 self-signature" (signed-by? ed (.getPublicKey ed)))))

(defn- test-explicit-certificate []
  (let [kp (keypair "EC")
        cert (x509/certificate {:subject "CN=explicit"
                                :public-key (.getPublic kp)
                                :signing-key (.getPrivate kp)
                                :serial 42
                                :not-before #inst "2026-01-01T00:00:00Z"
                                :not-after #inst "2051-06-01T12:30:00Z"})]
    (check ":serial 42" (= 42 (.getSerialNumber cert)))
    (check ":not-before is that instant" (= 1767225600000 (.getTime (.getNotBefore cert))))
    ;; 2050 and later is GeneralizedTime (RFC 5280 4.1.2.5)
    (check ":not-after past 2049 is that instant" (= (inst-ms #inst "2051-06-01T12:30:00Z")
                                                     (.getTime (.getNotAfter cert))))
    (check "the certificate carries the given public key"
           (ba= (.getEncoded (.getPublic kp)) (.getEncoded (.getPublicKey cert))))
    (check "OpenSSL verifies it" (signed-by? cert (.getPublic kp)))
    (check "a big serial survives"
           (let [s (- (apply * (repeat 159 2)) 1)]
             (= s (.getSerialNumber (x509/certificate {:subject "CN=x" :public-key (.getPublic kp)
                                                       :signing-key (.getPrivate kp) :serial s})))))
    (check "java.util.Date works for validity"
           (= 0 (.getTime (.getNotBefore (x509/certificate {:subject "CN=x" :public-key (.getPublic kp)
                                                            :signing-key (.getPrivate kp)
                                                            :not-before (java.util.Date. 0)
                                                            :days 1})))))))

(defn- test-ca-and-leaf []
  (let [{ca :certificate ca-key :private-key} (x509/generate {:subject "CN=Test CA,O=Jolt" :ca? true})
        {leaf :certificate} (x509/generate {:subject "CN=localhost"
                                            :issuer ca :signing-key ca-key
                                            :san localhost-san
                                            :key-usage #{:digital-signature :key-encipherment}
                                            :extended-key-usage #{:server-auth :client-auth}})
        {other :certificate} (x509/generate {:subject "CN=Other CA" :ca? true})]
    (check "a CA's basicConstraints is critical" (true? (ext-critical ca nid-basic-constraints)))
    (check "a CA is a CA" (pos? (bit-and (ext-flags ca) exflag-ca)))
    (check "a CA gets keyCertSign + cRLSign + digitalSignature by default"
           (= (bit-or 0x04 0x02 0x80) (key-usage ca)))
    (check "keyUsage is critical" (true? (ext-critical ca nid-key-usage)))
    (check "the CA is its own anchor" (zero? (chain-error [ca] ca)))
    (check "leaf issuer is the CA's subject" (= "CN=Test CA,O=Jolt" (.getName (.getIssuerX500Principal leaf))))
    (check "leaf subject" (= "CN=localhost" (.getName (.getSubjectX500Principal leaf))))
    (check "OpenSSL verifies the leaf with the CA key" (signed-by? leaf (.getPublicKey ca)))
    (check "the leaf's own key did not sign it" (not (signed-by? leaf (.getPublicKey leaf))))
    (check "X509_check_issued accepts the pair" (issued-by? ca leaf))
    (check "authorityKeyIdentifier is the CA's subjectKeyIdentifier" (akid-matches? ca leaf))
    (check "the leaf chains to the CA" (zero? (chain-error [ca] leaf)))
    (check "the leaf does not chain to another CA" (= 20 (chain-error [other] leaf)))
    (check "keyUsage as asked" (= (bit-or 0x80 0x20) (key-usage leaf)))
    (check "extendedKeyUsage as asked" (= (bit-or 0x1 0x2) (ext-key-usage leaf)))
    (check "leaf SAN" (and (host? leaf "localhost") (ip? leaf "::1")))
    ;; a CA-signed leaf from certificate, with keys in hand
    (let [kp (keypair "RSA")
          c (x509/certificate {:subject "CN=client" :public-key (.getPublic kp)
                               :signing-key ca-key :issuer ca
                               :extended-key-usage #{:client-auth}})]
      (check "certificate issues an RSA key under an EC CA"
             (and (= "SHA256withECDSA" (.getSigAlgName c)) (zero? (chain-error [ca] c))))))
  ;; an RSA CA signs SHA256withRSA, whatever the leaf's key
  (let [{ca :certificate ca-key :private-key} (x509/generate {:subject "CN=RSA CA" :ca? true :key-type :rsa})
        {leaf :certificate} (x509/generate {:subject "CN=leaf" :issuer ca :signing-key ca-key})]
    (check "an RSA CA signs SHA256withRSA" (= "SHA256withRSA" (.getSigAlgName leaf)))
    (check "an EC leaf chains to an RSA CA" (zero? (chain-error [ca] leaf)))))

(defn- test-names []
  (let [kp (keypair "EC")
        dn (fn [s] (try (.getName (.getSubjectX500Principal
                                   (x509/certificate {:subject s :public-key (.getPublic kp)
                                                      :signing-key (.getPrivate kp)})))
                        (catch Exception e [:threw (ex-message e)])))]
    (check "attribute order is kept" (= "CN=a,OU=b,O=c,L=d,ST=e,C=US" (dn "CN=a,OU=b,O=c,L=d,ST=e,C=US")))
    (check "an escaped comma round-trips" (= "CN=Example\\, Inc.,O=x" (dn "CN=Example\\, Inc.,O=x")))
    (check "an escaped plus round-trips" (= "CN=a\\+b" (dn "CN=a\\+b")))
    (check "spaces around separators are dropped" (= "CN=a b,O=c" (dn " CN = a b , O = c ")))
    ;; getName escapes non-ASCII (\\C3\\B6) where the JDK prints the character,
    ;; so check the encoding itself: a UTF8String (tag 12) of the value's bytes.
    (check "UTF-8 values are UTF8Strings"
           (let [der (.getEncoded (x509/certificate {:subject "CN=Jölt ✓" :public-key (.getPublic kp)
                                                     :signing-key (.getPrivate kp)}))
                 want (concat [12 9] (seq (.getBytes "Jölt ✓" "UTF-8")))]
             (some #(= want %) (partition (count want) 1 (seq der)))))
    (check "hex escapes are UTF-8" (= (dn "CN=é") (dn "CN=\\C3\\A9")))
    (check "lower-case attribute names" (= "CN=a,DC=example,DC=com" (dn "cn=a,dc=example,dc=com")))
    (check "a dotted OID names an attribute" (= "CN=byoid" (dn "2.5.4.3=byoid")))
    ;; X500Principal takes the RFC 1779 OID. prefix, in either case
    (check "an OID. prefix names an attribute" (= "CN=x" (dn "OID.2.5.4.3=x")))
    (check "an oid. prefix too" (= "CN=x" (dn "oid.2.5.4.3=x")))
    ;; X500Principal drops a trailing space after an escaped backslash
    ;; ("CN=a\\\\ " is CN=a\\) and keeps an escaped one ("CN=a\\ ")
    (check "a space after an escaped backslash is trimmed" (= "CN=a\\\\" (dn "CN=a\\\\ ")))
    (check "an escaped trailing space is kept" (= (dn "CN=a\\20") (dn "CN=a\\ ")))
    ;; RFC 4514 and X500Principal trim spaces only, so a tab stays in the value
    (let [utf8-in-der? (fn [subject value]
                         (let [der (.getEncoded (x509/certificate {:subject subject :public-key (.getPublic kp)
                                                                   :signing-key (.getPrivate kp)}))
                               bs (seq (.getBytes ^String value "UTF-8"))
                               want (concat [12 (count bs)] bs)]
                           (boolean (some #(= want %) (partition (count want) 1 (seq der))))))]
      (check "a leading tab is part of the value" (utf8-in-der? "CN=\ta" "\ta"))
      (check "a trailing tab is part of the value" (utf8-in-der? "CN=a\t" "a\t")))))

(defn- test-validation []
  (let [kp (keypair "EC") kp2 (keypair "EC")
        base {:subject "CN=x" :public-key (.getPublic kp) :signing-key (.getPrivate kp)}
        cert! (fn [opts] #(x509/certificate (merge base opts)))
        {ca :certificate ca-key :private-key} (x509/generate {:subject "CN=CA" :ca? true})
        leaf (x509/certificate base)]
    (check "a missing :subject is named" (rejects? ":subject" #(x509/certificate (dissoc base :subject))))
    (check "an empty DN" (rejects? ":subject" (cert! {:subject ""})))
    (check "a DN component without =" (rejects? "\"CN\"" (cert! {:subject "CN"})))
    (check "an unknown DN attribute is named" (rejects? "FOO" (cert! {:subject "FOO=bar"})))
    (check "an empty DN value" (rejects? "empty" (cert! {:subject "CN="})))
    (check "a trailing comma" (rejects? ":subject" (cert! {:subject "CN=a,"})))
    (check "a multi-valued RDN" (rejects? "multi-valued" (cert! {:subject "CN=a+O=b"})))
    (check "a dangling escape" (rejects? "escape" (cert! {:subject "CN=a\\"})))
    (check "OpenSSL's refusal names the attribute" (rejects? "C=USA" (cert! {:subject "C=USA"})))
    (check "a DN that is not a string" (rejects? ":subject" (cert! {:subject :cn})))
    (check "an unknown SAN kind is named" (rejects? ":uri" (cert! {:san [[:uri "https://x"]]})))
    (check "a bad IPv4 address is named" (rejects? "300.1.1.1" (cert! {:san [[:ip "300.1.1.1"]]})))
    (check "a bad IPv6 address is named" (rejects? "::1::2" (cert! {:san [[:ip "::1::2"]]})))
    (check "a bad DNS name is named" (rejects? "a,b" (cert! {:san [[:dns "a,b"]]})))
    (check "a SAN entry that is not a pair" (rejects? ":san" (cert! {:san [:dns "localhost"]})))
    (check "a missing :public-key" (rejects? ":public-key" #(x509/certificate (dissoc base :public-key))))
    (check "a missing :signing-key" (rejects? ":signing-key" #(x509/certificate (dissoc base :signing-key))))
    (check "a public key as :signing-key" (rejects? ":signing-key" (cert! {:signing-key (.getPublic kp)})))
    (check "a private key as :public-key" (rejects? ":public-key" (cert! {:public-key (.getPrivate kp)})))
    (check "a self-signed key mismatch" (rejects? "does not match" (cert! {:signing-key (.getPrivate kp2)})))
    (check "an issuer key mismatch" (rejects? "does not match the :issuer" (cert! {:issuer ca :signing-key (.getPrivate kp2)})))
    (check "an issuer that is not a CA" (rejects? "not a CA" (cert! {:issuer leaf})))
    (check "an issuer that is not a certificate" (rejects? ":issuer" (cert! {:issuer "CN=CA" :signing-key ca-key})))
    (check "an unsupported key algorithm"
           (rejects? "DSA" (cert! {:signing-key (doto (jolt.host/tagged-table :jolt.crypto/private-key)
                                                  (jolt.host/ref-put! :bytes (byte-array 4))
                                                  (jolt.host/ref-put! :algo "DSA"))})))
    (check "an unknown key usage is named" (rejects? ":bogus" (cert! {:key-usage #{:bogus}})))
    (check "an unknown extended key usage is named" (rejects? ":bogus" (cert! {:extended-key-usage #{:bogus}})))
    (check "an unknown option is named" (rejects? ":sans" (cert! {:sans []})))
    (check ":days must be positive" (rejects? ":days" (cert! {:days 0})))
    (check ":days and :not-after together" (rejects? ":not-after" (cert! {:days 1 :not-after #inst "2030-01-01"})))
    (check ":not-after before :not-before"
           (rejects? ":not-after" (cert! {:not-before #inst "2030-01-01" :not-after #inst "2029-01-01"})))
    (check "a validity that is not an instant" (rejects? ":not-before" (cert! {:not-before "2030-01-01"})))
    (check "serial 0" (rejects? ":serial" (cert! {:serial 0})))
    (check "a negative serial" (rejects? ":serial" (cert! {:serial -5})))
    (check "a serial of 2^159 is too long" (rejects? ":serial" (cert! {:serial (apply * (repeat 159 2))})))
    (check "generate: an unknown :key-type is named" (rejects? ":dsa" #(x509/generate {:subject "CN=x" :key-type :dsa})))
    (check "generate: :issuer without :signing-key" (rejects? ":signing-key" #(x509/generate {:subject "CN=x" :issuer ca})))
    (check "generate: :signing-key without :issuer"
           (rejects? ":signing-key" #(x509/generate {:subject "CN=x" :signing-key (.getPrivate kp)})))
    ;; X500Principal decodes #hex as a BER value; this builder refuses it
    ;; rather than storing the text "#0c03616263"
    (check "a #hex BER value is refused" (rejects? "#" (cert! {:subject "CN=#0c03616263"})))
    (check "hex escapes that are not UTF-8 are refused" (rejects? "UTF-8" (cert! {:subject "CN=\\C3"})))
    (doseq [ip ["1.2.3.4abc" "1.2.3.4,x" "1.2.3.4 " "+1.2.3.4" "1.2.3.4.5" " 1.2.3.4" "01.2.3.4" "::ffff:1.2.3.4x"]]
      (check (str "a malformed IP " (pr-str ip) " is refused")
             (rejects? "bad IP address" (cert! {:san [[:ip ip]]}))))
    (check "an IPv4-mapped IPv6 address is accepted"
           (ip? (x509/certificate (merge base {:san [[:ip "::ffff:1.2.3.4"]]})) "::ffff:1.2.3.4"))
    (check "a CA keyUsage without :key-cert-sign is refused"
           (rejects? ":key-cert-sign" (cert! {:ca? true :key-usage #{:digital-signature}})))
    (check ":key-usage as a map is refused" (rejects? "a set" (cert! {:key-usage {:digital-signature true}})))
    (check "generate: :key-size with :ed25519"
           (rejects? ":key-size" #(x509/generate {:subject "CN=x" :key-type :ed25519 :key-size 256})))
    (check "generate: :public-key is not an option" (rejects? ":public-key" #(x509/generate {:subject "CN=x" :public-key (.getPublic kp)})))))

(defn- push-stale-error!
  "Leave an unrelated error on this thread's OpenSSL queue, as other code can."
  []
  (let [junk (byte-array [1 2 3 4])
        buf (ffi/alloc 4) holder (ffi/alloc ptr-size)]
    (try (ffi/write-array buf junk) (ffi/write holder :pointer buf 0)
         (t-d2i-x509 ffi/null holder 4)
         (finally (ffi/free buf) (ffi/free holder))))
  (pos? (t-err-peek)))

(defn- test-error-queue []
  (let [kp (keypair "EC")
        base {:subject "CN=x" :public-key (.getPublic kp) :signing-key (.getPrivate kp)}]
    (check "the probe leaves a stale error" (push-stale-error!))
    (let [m (error-message #(x509/certificate (assoc base :subject "C=USA")))]
      (check (str "a native failure reports its own reason, not a stale one: " m)
             (and (str/includes? m "C=USA") (str/includes? m "string too long"))))
    (check "a failure leaves the queue empty" (zero? (t-err-peek)))
    (push-stale-error!)
    (x509/certificate base)
    (check "a success leaves the queue empty" (zero? (t-err-peek)))))

(defn- test-pem []
  (let [{:keys [certificate private-key]} (x509/generate {:subject "CN=pem"})
        cpem (x509/pem certificate)
        kpem (x509/pem private-key)
        body (fn [p] (->> (str/split-lines p) (remove #(str/starts-with? % "-----")) (apply str)))
        decode (fn [p] (.decode (java.util.Base64/getDecoder) ^String (body p)))]
    (check "a certificate PEM" (and (str/starts-with? cpem "-----BEGIN CERTIFICATE-----\n")
                                    (str/ends-with? cpem "-----END CERTIFICATE-----\n")))
    (check "PEM lines are at most 64 characters" (every? #(<= (count %) 64) (str/split-lines cpem)))
    (check "the PEM parses back to the same certificate"
           (= certificate (.generateCertificate (CertificateFactory/getInstance "X.509")
                                                (java.io.ByteArrayInputStream. (.getBytes cpem)))))
    (check "a private key PEM is PKCS#8" (and (str/starts-with? kpem "-----BEGIN PRIVATE KEY-----\n")
                                              (ba= (.getEncoded private-key) (decode kpem))))
    (check "a public key PEM is SPKI"
           (let [p (x509/pem (.getPublicKey certificate))]
             (and (str/starts-with? p "-----BEGIN PUBLIC KEY-----\n")
                  (ba= (.getEncoded (.getPublicKey certificate)) (decode p)))))
    (check "pem refuses anything else" (rejects? "pem" #(x509/pem "nope")))))

(defn run
  "Run every check; answer the number that failed."
  []
  (reset! failures 0)
  (test-self-signed-ec)
  (test-key-types)
  (test-explicit-certificate)
  (test-ca-and-leaf)
  (test-names)
  (test-validation)
  (test-error-queue)
  (test-pem)
  @failures)
