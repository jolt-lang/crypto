(ns jolt.crypto.x509
  "Make X.509 certificates: self-signed ones for a test or dev TLS server, and
  small CAs with the leaves they issue for mTLS tests.

  The JDK has no public certificate builder (a JVM program shells out to
  keytool or pulls in Bouncy Castle), so there is no class to mirror and this is
  a plain function API instead: an options map in, the same X509Certificate
  value CertificateFactory returns out.

    (certificate opts)   build and sign a certificate for a public key you have
    (generate opts)      generate a key pair too: {:certificate :private-key}
    (pem x)              PEM text for a certificate, private key or public key

  Every certificate is v3, signed SHA-256 with RSA or ECDSA, or Ed25519, as the
  signing key's type dictates. It carries subjectKeyIdentifier, basicConstraints
  (critical on a CA), authorityKeyIdentifier when an issuer signs it, and the
  subjectAltName, keyUsage and extendedKeyUsage asked for.

  Built over OpenSSL's libcrypto through jolt.ffi with functions OpenSSL 1.1.0
  and 3.x both export. Every native object is freed before the call returns,
  whether it returns or throws."
  (:require [clojure.string :as str]
            [jolt.crypto :as crypto]
            [jolt.ffi :as ffi]))

(import '[java.security KeyPairGenerator])
(import '[java.security.cert CertificateFactory X509Certificate])

;; --- OpenSSL bindings ---------------------------------------------------------
(ffi/defcfn c-x509-new          "X509_new"                   [] :pointer)
(ffi/defcfn c-x509-free         "X509_free"                  [:pointer] :void)
(ffi/defcfn c-x509-set-version  "X509_set_version"           [:pointer :long] :int)
(ffi/defcfn c-x509-serial       "X509_get_serialNumber"      [:pointer] :pointer)
(ffi/defcfn c-bn-hex2bn         "BN_hex2bn"                  [:pointer :string] :int)
(ffi/defcfn c-bn-to-asn1-int    "BN_to_ASN1_INTEGER"         [:pointer :pointer] :pointer)
(ffi/defcfn c-bn-free           "BN_free"                    [:pointer] :void)
(ffi/defcfn c-getm-not-before   "X509_getm_notBefore"        [:pointer] :pointer)
(ffi/defcfn c-getm-not-after    "X509_getm_notAfter"         [:pointer] :pointer)
(ffi/defcfn c-asn1-time-set     "ASN1_TIME_set"              [:pointer :long] :pointer)
(ffi/defcfn c-name-new          "X509_NAME_new"              [] :pointer)
(ffi/defcfn c-name-free         "X509_NAME_free"             [:pointer] :void)
(ffi/defcfn c-name-add-txt      "X509_NAME_add_entry_by_txt" [:pointer :string :int :string :int :int :int] :int)
(ffi/defcfn c-x509-set-subject  "X509_set_subject_name"      [:pointer :pointer] :int)
(ffi/defcfn c-x509-set-issuer   "X509_set_issuer_name"       [:pointer :pointer] :int)
(ffi/defcfn c-x509-get-subject  "X509_get_subject_name"      [:pointer] :pointer)
(ffi/defcfn c-x509-set-pubkey   "X509_set_pubkey"            [:pointer :pointer] :int)
(ffi/defcfn c-v3-set-ctx        "X509V3_set_ctx"             [:pointer :pointer :pointer :pointer :pointer :int] :void)
(ffi/defcfn c-v3-ext-conf-nid   "X509V3_EXT_conf_nid"        [:pointer :pointer :int :string] :pointer)
(ffi/defcfn c-x509-add-ext      "X509_add_ext"               [:pointer :pointer :int] :int)
(ffi/defcfn c-ext-free          "X509_EXTENSION_free"        [:pointer] :void)
(ffi/defcfn c-x509-sign         "X509_sign"                  [:pointer :pointer :pointer] :int)
(ffi/defcfn c-sha256            "EVP_sha256"                 [] :pointer)
(ffi/defcfn c-i2d-x509          "i2d_X509"                   [:pointer :pointer] :int)
(ffi/defcfn c-d2i-x509          "d2i_X509"                   [:pointer :pointer :long] :pointer)
(ffi/defcfn c-d2i-pubkey        "d2i_PUBKEY"                 [:pointer :pointer :long] :pointer)
(ffi/defcfn c-d2i-privkey       "d2i_AutoPrivateKey"         [:pointer :pointer :long] :pointer)
(ffi/defcfn c-pkey-free         "EVP_PKEY_free"              [:pointer] :void)
(ffi/defcfn c-check-private-key "X509_check_private_key"     [:pointer :pointer] :int)
(ffi/defcfn c-check-ca          "X509_check_ca"              [:pointer] :int)
(ffi/defcfn c-a2i-ipaddress     "a2i_IPADDRESS"              [:string] :pointer)
(ffi/defcfn c-octet-free        "ASN1_OCTET_STRING_free"     [:pointer] :void)
(ffi/defcfn c-err-get           "ERR_get_error"              [] :ulong)
(ffi/defcfn c-err-string        "ERR_error_string_n"         [:ulong :pointer :size_t] :void)
(ffi/defcfn c-err-clear         "ERR_clear_error"            [] :void)

(def ^:private ptr-size (ffi/sizeof :pointer))
(def ^:private mbstring-utf8 0x1000)
(def ^:private x509-version-3 2)
(def ^:private nid-subject-key-identifier 82)
(def ^:private nid-key-usage 83)
(def ^:private nid-subject-alt-name 85)
(def ^:private nid-basic-constraints 87)
(def ^:private nid-authority-key-identifier 90)
(def ^:private nid-ext-key-usage 126)
;; struct v3_ext_ctx is eight pointer-sized fields in OpenSSL 3; X509V3_set_ctx
;; fills it. Allocated with room to spare, since the header says more may come.
(def ^:private v3-ctx-size 256)

;; --- errors and native lifetimes ------------------------------------------------
(defn- fail
  ([msg] (fail msg {}))
  ([msg data] (throw (ex-info (str "x509: " msg) data))))

(defn- openssl-reason
  "The oldest error on this thread's OpenSSL queue as text, and the queue
  cleared; nil when it was empty. certificate clears the queue before its first
  native call, so the oldest entry is the root cause of this call's failure
  rather than something an earlier caller left behind."
  []
  (let [e (c-err-get)]
    (try
      (when-not (zero? e)
        (let [buf (ffi/alloc 256)]
          (try (c-err-string e buf 256) (ffi/ptr->string buf)
               (finally (ffi/free buf)))))
      (finally (c-err-clear)))))

(defn- native-fail [what data]
  (let [reason (openssl-reason)]
    (fail (str what (when reason (str " (" reason ")"))) data)))

(defn- with-owner
  "Call (f own). (own ptr free what) takes ownership of a native object, after
  refusing a NULL one as the failure of `what`, and answers it. Everything owned
  is freed, last first, when f returns or throws."
  [f]
  (let [owned (atom ())]
    (try
      (f (fn [ptr free what]
           (when (ffi/null? ptr) (native-fail (str what " failed") {}))
           (swap! owned conj [ptr free])
           ptr))
      (finally
        (doseq [[ptr free] @owned] (free ptr))
        ;; a failure path has already reported what it found; a success
        ;; path must not leave anything behind either
        (c-err-clear)))))

(defn- d2i
  "Decode DER with a d2i_* parser into an owned object."
  [own d2i-fn free der what]
  (let [n (alength der)
        buf (own (ffi/alloc (max 1 n)) ffi/free "alloc")
        holder (own (ffi/alloc ptr-size) ffi/free "alloc")]
    (ffi/write-array buf der)
    (ffi/write holder :pointer buf 0)
    (own (d2i-fn ffi/null holder n) free what)))

(defn- der-out
  "The DER an i2d_* encoder writes for obj."
  [i2d-fn obj]
  (let [len (i2d-fn obj ffi/null)]
    (when (<= len 0) (native-fail "DER encoding failed" {}))
    (let [buf (ffi/alloc len) holder (ffi/alloc ptr-size)]
      (try
        (ffi/write holder :pointer buf 0)
        (let [n (i2d-fn obj holder)]
          (when (<= n 0) (native-fail "DER encoding failed" {}))
          (ffi/read-array buf n))
        (finally (ffi/free buf) (ffi/free holder))))))

;; --- distinguished names -------------------------------------------------------
;; The RFC 2253 attribute keywords X500Principal parses, plus the two RFC 1779 /
;; PKCS#9 ones certificates often carry, mapped to OpenSSL's names for them. A
;; dotted OID names any other attribute.
(def ^:private dn-attributes
  {"CN" "CN" "C" "C" "L" "L" "ST" "ST" "O" "O" "OU" "OU" "STREET" "street"
   "DC" "DC" "UID" "UID" "EMAILADDRESS" "emailAddress" "SERIALNUMBER" "serialNumber"})

(def ^:private dn-specials #{\, \= \+ \< \> \# \; \\ \" \space})

(defn- hex-digit? [c] (boolean (re-matches #"[0-9A-Fa-f]" (str c))))

(defn- split-unescaped
  "Split s at every unescaped `sep`, keeping escapes in the pieces."
  [s sep]
  (let [n (count s)]
    (loop [i 0 start 0 acc []]
      (cond (>= i n) (conj acc (subs s start))
            (= \\ (nth s i)) (recur (+ i 2) start acc)
            (= sep (nth s i)) (recur (inc i) (inc i) (conj acc (subs s start i)))
            :else (recur (inc i) start acc)))))

(defn- escaped-at?
  "Whether the character at index i of s is escaped: an odd run of backslashes
  right before it."
  [s i]
  (odd? (count (take-while #(= \\ %) (map #(nth s %) (range (dec i) -1 -1))))))

(defn- trim-value
  "Drop leading spaces and trailing unescaped ones. Spaces only, as RFC 4514
  and X500Principal trim: a tab or newline is part of the value."
  [s]
  (let [s (subs s (count (take-while #(= \space %) s)))]
    (loop [s s]
      (let [i (dec (count s))]
        (if (and (>= i 0) (= \space (nth s i)) (not (escaped-at? s i)))
          (recur (subs s 0 i))
          s)))))

(defn- unescape-value
  "An RFC 2253 attribute value with its escapes resolved: \\, and the other
  specials stand for themselves, \\XX is one byte, and the bytes are UTF-8."
  [dn raw]
  (let [n (count raw)
        utf8 (fn [c] (seq (.getBytes (str c) "UTF-8")))]
    (when (and (pos? n) (= \# (nth raw 0)))
      ;; RFC 4514 #hexstring is a BER-encoded value, which X500Principal
      ;; decodes. Storing it as the literal text would be silently wrong.
      (fail (str "#hex BER values are not supported in " (pr-str dn)
                 " (write the value as text, or escape a literal # as \\#)") {:subject dn}))
    (loop [i 0 out []]
      (if (>= i n)
        (let [bs (byte-array out) v (String. bs "UTF-8")]
          ;; \XX escapes can spell bytes that are not UTF-8, which would
          ;; decode to replacement characters (X500Principal keeps U+FFFD)
          (when-not (= (seq bs) (seq (.getBytes v "UTF-8")))
            (fail (str "the \\XX escapes in " (pr-str dn) " are not valid UTF-8") {:subject dn}))
          v)
        (let [c (nth raw i)]
          (cond
            (not= \\ c)
            (do (when (#{\+} c)
                  (fail (str "multi-valued RDNs are not supported in " (pr-str dn)
                             " (escape a literal + as \\+)") {:subject dn}))
                (when (#{\" \< \> \;} c)
                  (fail (str "unescaped " c " in " (pr-str dn)) {:subject dn}))
                (recur (inc i) (into out (utf8 c))))

            (>= (inc i) n)
            (fail (str "dangling escape at the end of " (pr-str dn)) {:subject dn})

            (and (< (+ i 2) n) (hex-digit? (nth raw (inc i))) (hex-digit? (nth raw (+ i 2))))
            (recur (+ i 3) (conj out (unchecked-byte (Integer/parseInt (subs raw (inc i) (+ i 3)) 16))))

            (dn-specials (nth raw (inc i)))
            (recur (+ i 2) (into out (utf8 (nth raw (inc i)))))

            :else
            (fail (str "bad escape \\" (nth raw (inc i)) " in " (pr-str dn)) {:subject dn})))))))

(defn- parse-dn
  "An RFC 2253 / X500Principal string as [[openssl-field value] ...] in the
  order the string lists them, most specific first."
  [dn]
  (when-not (string? dn)
    (fail (str ":subject must be an RFC 2253 string such as \"CN=localhost,O=Example\", got "
               (pr-str dn)) {:subject dn}))
  (when (str/blank? dn)
    (fail ":subject must name at least one attribute, e.g. \"CN=localhost\"" {:subject dn}))
  (mapv (fn [rdn]
          (let [[k :as parts] (split-unescaped rdn \=)
                k (str/trim (or k ""))]
            (when (< (count parts) 2)
              (fail (str ":subject component " (pr-str (str/trim rdn)) " is not ATTRIBUTE=value") {:subject dn}))
            (let [oid (if (re-matches #"(?i)oid\..*" k) (subs k 4) k)
                  field (or (dn-attributes (str/upper-case k))
                            (when (re-matches #"[0-9]+(\.[0-9]+)+" oid) oid)
                            (fail (str ":subject attribute " (pr-str k) " is unknown (use one of "
                                       (str/join ", " (sort (keys dn-attributes))) " or a dotted OID)")
                                  {:subject dn :attribute k}))
                  ;; the value may hold escaped = signs, so rejoin what split off
                  raw (trim-value (str/join "=" (rest parts)))
                  value (unescape-value dn raw)]
              (when (str/blank? value)
                (fail (str ":subject attribute " k " has an empty value") {:subject dn :attribute k}))
              (when (str/includes? value "\u0000")
                (fail (str ":subject attribute " k " holds a NUL byte") {:subject dn :attribute k}))
              [k field value])))
        (split-unescaped dn \,)))

(defn- build-name
  "An owned X509_NAME for dn. RFC 2253 lists the most specific RDN first and the
  encoding holds it last, so the attributes go in reversed."
  [own dn]
  (let [nm (own (c-name-new) c-name-free "X509_NAME_new")]
    (doseq [[k field value] (rseq (parse-dn dn))]
      (when (not= 1 (c-name-add-txt nm field mbstring-utf8 value -1 -1 0))
        (native-fail (str ":subject attribute " k "=" value " was refused by OpenSSL")
                     {:subject dn :attribute k})))
    nm))

;; --- extensions ----------------------------------------------------------------
(def ^:private key-usages
  {:digital-signature "digitalSignature" :non-repudiation "nonRepudiation"
   :content-commitment "nonRepudiation" :key-encipherment "keyEncipherment"
   :data-encipherment "dataEncipherment" :key-agreement "keyAgreement"
   :key-cert-sign "keyCertSign" :crl-sign "cRLSign"
   :encipher-only "encipherOnly" :decipher-only "decipherOnly"})

(def ^:private extended-key-usages
  {:server-auth "serverAuth" :client-auth "clientAuth" :code-signing "codeSigning"
   :email-protection "emailProtection" :time-stamping "timeStamping"
   :ocsp-signing "OCSPSigning"})

(def ^:private ca-key-usage #{:key-cert-sign :crl-sign :digital-signature})

(defn- usage-conf
  "The extension config string for a set of usage keywords, or nil when empty."
  [opt table usages]
  (when (and (some? usages) (not (or (set? usages) (sequential? usages))))
    (fail (str opt " must be a set of keywords, got " (pr-str usages)) {opt usages}))
  (when (seq usages)
    (str/join "," (for [u (sort-by str usages)]
                    (or (table u)
                        (fail (str "unknown " opt " " (pr-str u) " (expected one of "
                                   (str/join ", " (sort (map str (keys table)))) ")")
                              {opt usages :value u}))))))

;; Labels, plus an optional trailing dot and a leading *. wildcard. Nothing that
;; would end an entry in OpenSSL's config syntax (comma, colon, space) gets past.
(def ^:private dns-name-re #"(\*\.)?[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?")

;; a2i_IPADDRESS is the parser OpenSSL builds the SAN with, but older releases
;; read IPv4 with sscanf("%d.%d.%d.%d"), which takes "+1.2.3.4" and ignores
;; anything after the fourth octet. So the text must be an address on its own
;; first: four 0-255 octets without leading zeros, or IPv6 hex groups (whose
;; tail may be such an IPv4 address). 3.5.9 refuses all of these itself.
(def ^:private ipv4-octet "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])")
(def ^:private ipv4-re (re-pattern (str ipv4-octet "(\\." ipv4-octet "){3}")))
(def ^:private ipv6-re (re-pattern (str "[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(" ipv4-octet "(\\." ipv4-octet "){3})?")))

(defn- valid-ip? [s]
  (let [o (when (or (re-matches ipv4-re s) (re-matches ipv6-re s)) (c-a2i-ipaddress s))]
    (if (or (nil? o) (ffi/null? o))
      (do (c-err-clear) false)
      (do (c-octet-free o) true))))

(defn- san-conf
  "The subjectAltName config string for [[:dns name] [:ip addr] ...], or nil."
  [san]
  (when (and (some? san) (not (sequential? san)))
    (fail (str ":san must be a vector of [kind value] pairs, got " (pr-str san)) {:san san}))
  (when (seq san)
    (str/join ","
              (for [entry san]
                (let [[kind v] (when (and (sequential? entry) (= 2 (count entry))) entry)]
                  (when-not (string? v)
                    (fail (str ":san entries are [kind value] pairs such as [:dns \"localhost\"], got "
                               (pr-str entry)) {:san san}))
                  (case kind
                    :dns (if (and (<= (count v) 253) (re-matches dns-name-re v))
                           (str "DNS:" v)
                           (fail (str "bad DNS name in :san: " (pr-str v)) {:san san :value v}))
                    :ip (if (valid-ip? v)
                          (str "IP:" v)
                          (fail (str "bad IP address in :san: " (pr-str v)) {:san san :value v}))
                    (fail (str "unknown :san kind " (pr-str kind) " (expected :dns or :ip)")
                          {:san san :kind kind})))))))

(defn- add-ext!
  "Build the extension `nid` from OpenSSL's config syntax and add it to x."
  [own x ctx nid conf label]
  (let [ext (own (c-v3-ext-conf-nid ffi/null ctx nid conf) c-ext-free
                 (str "building " label " (" conf ")"))]
    (when (not= 1 (c-x509-add-ext x ext -1))
      (native-fail (str "adding " label) {}))))

;; --- options -------------------------------------------------------------------
(def ^:private certificate-options
  #{:subject :public-key :signing-key :issuer :san :days :not-before :not-after
    :serial :ca? :key-usage :extended-key-usage})

(defn- check-options [opts allowed fn-name]
  (when-not (map? opts)
    (fail (str fn-name " takes an options map, got " (pr-str opts)) {}))
  (doseq [k (keys opts)]
    (when-not (allowed k)
      (fail (str "unknown option " (pr-str k) " to " fn-name " (expected one of "
                 (str/join ", " (sort (map str allowed))) ")")
            {:option k}))))

(defn- key-kind [k] (when (jolt.host/table? k) (jolt.host/ref-get k :jolt/type)))

(defn- key-der
  "The DER of a jolt-crypto key, after checking it is the kind `opt` wants."
  [opt k want]
  (when (nil? k) (fail (str "missing " opt) {:option opt}))
  (when-not (= want (key-kind k))
    (fail (str opt " must be a jolt-crypto "
               (if (= want :jolt.crypto/public-key) "PublicKey (X.509)" "PrivateKey (PKCS#8)")
               ", got " (if (#{:jolt.crypto/public-key :jolt.crypto/private-key} (key-kind k))
                          (str "a " (.getFormat k) " key")
                          (pr-str k)))
          {:option opt}))
  (.getEncoded k))

(defn- signing-digest
  "The digest X509_sign takes for a key algorithm: SHA-256 for RSA and ECDSA,
  none for Ed25519, which hashes internally."
  [algo]
  (case algo
    ("RSA" "EC") (c-sha256)
    "EdDSA" ffi/null
    (fail (str "unsupported :signing-key algorithm " (pr-str algo) " (expected RSA, EC or EdDSA)")
          {:algorithm algo})))

(defn- instant-ms [opt v]
  (if (inst? v)
    (inst-ms v)
    (fail (str opt " must be a java.util.Date or inst, got " (pr-str v)) {:option opt})))

(defn- validity
  "[not-before not-after] in epoch seconds."
  [{:keys [days not-before not-after]}]
  (when (and days not-after)
    (fail "give :days or :not-after, not both" {}))
  (when (and (some? days) (not (and (integer? days) (pos? days))))
    (fail (str ":days must be a positive integer, got " (pr-str days)) {:days days}))
  (let [nb (quot (if (some? not-before) (instant-ms :not-before not-before) (System/currentTimeMillis)) 1000)
        na (if (some? not-after)
             (quot (instant-ms :not-after not-after) 1000)
             (+ nb (* 86400 (or days 365))))]
    (when-not (< nb na)
      (fail ":not-after must be later than :not-before" {}))
    [nb na]))

;; RFC 5280 4.1.2.2: a positive INTEGER of at most 20 octets.
(def ^:private serial-limit (apply * (repeat 159 2)))

(defn- serial-hex [serial]
  (if (some? serial)
    (if (and (integer? serial) (pos? serial) (< serial serial-limit))
      (format "%x" serial)
      (fail (str ":serial must be a positive integer below 2^159 (20 octets), got " (pr-str serial))
            {:serial serial}))
    ;; 159 random bits: 20 bytes with the top bit clear, so the INTEGER is
    ;; positive and at most 20 octets. A zero draw is not a positive serial.
    (let [b (crypto/random-bytes 20)
          hex (apply str (map-indexed (fn [i v] (format "%02x" (cond-> (bit-and v 0xff) (zero? i) (bit-and 0x7f))))
                                      (seq b)))]
      (if (re-matches #"0+" hex) "1" hex))))

;; --- certificate ---------------------------------------------------------------
(defn- set-serial! [own x hex]
  (let [holder (own (ffi/alloc ptr-size) ffi/free "alloc")]
    (ffi/write holder :pointer ffi/null 0)
    (when (zero? (c-bn-hex2bn holder hex)) (native-fail "BN_hex2bn" {}))
    (let [bn (own (ffi/read holder :pointer) c-bn-free "BN_hex2bn")]
      (when (ffi/null? (c-bn-to-asn1-int bn (c-x509-serial x)))
        (native-fail "setting the serial number" {})))))

(defn- set-time! [getm x secs label]
  (when (ffi/null? (c-asn1-time-set (getm x) secs))
    (native-fail (str "setting " label) {})))

(defn certificate
  "Build and sign an X.509 v3 certificate; answers the same X509Certificate
  value CertificateFactory/generateCertificate returns.

  Options:
    :subject      RFC 2253 / X500Principal string, \"CN=localhost,O=Example\" (required)
    :public-key   the subject's jolt-crypto PublicKey (required)
    :signing-key  the jolt-crypto PrivateKey that signs: the subject's own for a
                  self-signed certificate, the issuer's otherwise (required)
    :issuer       the issuing CA's X509Certificate; absent means self-signed
    :san          [[:dns \"localhost\"] [:ip \"127.0.0.1\"] [:ip \"::1\"]]
    :days         validity in days from :not-before (default 365)
    :not-before   java.util.Date / inst (default now)
    :not-after    java.util.Date / inst, instead of :days
    :serial       positive integer below 2^159 (default 159 random bits)
    :ca?          true makes a CA: critical basicConstraints CA:TRUE, and keyUsage
                  keyCertSign, cRLSign, digitalSignature unless :key-usage says
                  otherwise (default false: basicConstraints CA:FALSE)
    :key-usage    #{:digital-signature :non-repudiation :key-encipherment
                    :data-encipherment :key-agreement :key-cert-sign :crl-sign
                    :encipher-only :decipher-only}, marked critical
    :extended-key-usage #{:server-auth :client-auth :code-signing
                          :email-protection :time-stamping :ocsp-signing}

  The signature is SHA256withRSA, SHA256withECDSA or Ed25519, from the signing
  key's algorithm. An issuer-signed certificate carries authorityKeyIdentifier;
  every certificate carries subjectKeyIdentifier. Bad options throw ex-info
  naming what is wrong."
  [opts]
  (check-options opts certificate-options "certificate")
  (c-err-clear)
  (let [{:keys [subject public-key signing-key issuer san ca? key-usage extended-key-usage serial]} opts
        _ (parse-dn subject)
        pub-der (key-der :public-key public-key :jolt.crypto/public-key)
        priv-der (key-der :signing-key signing-key :jolt.crypto/private-key)
        md (signing-digest (.getAlgorithm signing-key))
        _ (when (and (some? issuer) (not (instance? X509Certificate issuer)))
            (fail (str ":issuer must be an X509Certificate, got " (pr-str issuer)) {:option :issuer}))
        [not-before not-after] (validity opts)
        serial (serial-hex serial)
        san (san-conf san)
        ku (usage-conf :key-usage key-usages (if (and ca? (nil? key-usage)) ca-key-usage key-usage))
        _ (when (and ca? (some? key-usage) (not (some #{:key-cert-sign} key-usage)))
            (fail ":ca? true needs :key-cert-sign in :key-usage, or a CA cannot issue certificates"
                  {:key-usage key-usage}))
        eku (usage-conf :extended-key-usage extended-key-usages extended-key-usage)
        der (with-owner
              (fn [own]
                (let [pub (d2i own c-d2i-pubkey c-pkey-free pub-der "decoding :public-key")
                      priv (d2i own c-d2i-privkey c-pkey-free priv-der "decoding :signing-key")
                      issuer-x (when issuer
                                 (d2i own c-d2i-x509 c-x509-free (.getEncoded issuer) "decoding :issuer"))
                      x (own (c-x509-new) c-x509-free "X509_new")
                      subject-name (build-name own subject)
                      ctx (own (ffi/alloc v3-ctx-size) ffi/free "alloc")]
                  (when issuer-x
                    (when (zero? (c-check-ca issuer-x))
                      (c-err-clear)
                      (fail (str ":issuer " (.getName (.getSubjectX500Principal issuer))
                                 " is not a CA (it needs basicConstraints CA:TRUE)") {:option :issuer}))
                    (when (not= 1 (c-check-private-key issuer-x priv))
                      (c-err-clear)
                      (fail ":signing-key does not match the :issuer certificate's public key"
                            {:option :signing-key})))
                  (when (not= 1 (c-x509-set-version x x509-version-3)) (native-fail "X509_set_version" {}))
                  (set-serial! own x serial)
                  (set-time! c-getm-not-before x not-before "notBefore")
                  (set-time! c-getm-not-after x not-after "notAfter")
                  (when (not= 1 (c-x509-set-subject x subject-name)) (native-fail "setting the subject" {}))
                  (when (not= 1 (c-x509-set-issuer x (if issuer-x (c-x509-get-subject issuer-x) subject-name)))
                    (native-fail "setting the issuer" {}))
                  (when (not= 1 (c-x509-set-pubkey x pub)) (native-fail "setting the public key" {}))
                  (when (and (nil? issuer-x) (not= 1 (c-check-private-key x priv)))
                    (c-err-clear)
                    (fail ":signing-key does not match :public-key, and a certificate without :issuer is self-signed"
                          {:option :signing-key}))
                  (c-v3-set-ctx ctx (or issuer-x x) x ffi/null ffi/null 0)
                  (add-ext! own x ctx nid-basic-constraints (if ca? "critical,CA:TRUE" "CA:FALSE") "basicConstraints")
                  (when ku (add-ext! own x ctx nid-key-usage (str "critical," ku) "keyUsage"))
                  (when eku (add-ext! own x ctx nid-ext-key-usage eku "extendedKeyUsage"))
                  (when san (add-ext! own x ctx nid-subject-alt-name san "subjectAltName"))
                  (add-ext! own x ctx nid-subject-key-identifier "hash" "subjectKeyIdentifier")
                  (when issuer-x
                    (add-ext! own x ctx nid-authority-key-identifier "keyid,issuer" "authorityKeyIdentifier"))
                  (when (<= (c-x509-sign x priv md) 0) (native-fail "signing the certificate" {}))
                  (der-out c-i2d-x509 x))))]
    (.generateCertificate (CertificateFactory/getInstance "X.509") der)))

(def ^:private generate-options
  (-> certificate-options (disj :public-key) (conj :key-type :key-size)))

(defn generate
  "Generate a key pair and a certificate for it; answers {:certificate
  X509Certificate :private-key PrivateKey}.

  Takes certificate's options except :public-key, plus:
    :key-type  :ec (default, P-256), :rsa (default 2048 bits) or :ed25519
    :key-size  RSA modulus bits, or 256 / 384 / 521 to pick an EC curve

  Without :issuer the certificate is self-signed with the new key. With :issuer
  it is issued by that CA, and :signing-key must be the CA's private key."
  [opts]
  (check-options opts generate-options "generate")
  (let [{:keys [key-type key-size issuer signing-key] :or {key-type :ec}} opts
        algo (case key-type :ec "EC" :rsa "RSA" :ed25519 "Ed25519"
                   (fail (str "unknown :key-type " (pr-str key-type) " (expected :ec, :rsa or :ed25519)")
                         {:key-type key-type}))
        _ (when (and (= :ed25519 key-type) (some? key-size))
            (fail ":key-size does not apply to :ed25519, which has one size" {:key-size key-size}))
        _ (when (and issuer (nil? signing-key))
            (fail "an :issuer needs its :signing-key, the CA's private key" {:option :signing-key}))
        _ (when (and signing-key (nil? issuer))
            (fail "a :signing-key without :issuer: generate self-signs with the key pair it makes"
                  {:option :signing-key}))
        kpg (KeyPairGenerator/getInstance algo)
        _ (when (some? key-size) (.initialize kpg key-size))
        kp (.generateKeyPair kpg)
        priv (.getPrivate kp)]
    {:certificate (certificate (-> opts
                                   (dissoc :key-type :key-size)
                                   (assoc :public-key (.getPublic kp))
                                   (cond-> (nil? issuer) (assoc :signing-key priv))))
     :private-key priv}))

;; --- PEM -----------------------------------------------------------------------
(defn pem
  "PEM text for an X509Certificate (CERTIFICATE), a jolt-crypto PrivateKey
  (PKCS#8 PRIVATE KEY) or PublicKey (SubjectPublicKeyInfo PUBLIC KEY): what
  `openssl` and a TLS server's key/certificate files expect."
  [x]
  (let [label (cond (instance? X509Certificate x) "CERTIFICATE"
                    (= :jolt.crypto/private-key (key-kind x)) "PRIVATE KEY"
                    (= :jolt.crypto/public-key (key-kind x)) "PUBLIC KEY"
                    :else (fail (str "pem takes an X509Certificate, PrivateKey or PublicKey, got " (pr-str x)) {}))
        b64 (.encodeToString (java.util.Base64/getEncoder) (.getEncoded x))
        lines (map #(apply str %) (partition-all 64 b64))]
    (str "-----BEGIN " label "-----\n"
         (apply str (map #(str % "\n") lines))
         "-----END " label "-----\n")))
