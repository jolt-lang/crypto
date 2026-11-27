(ns jolt.crypto.internal.libcrypto
  "The libcrypto functions jolt.crypto binds through jolt.ffi: the EVP
  cipher, digest, HMAC and key APIs, the RSA, EC and BIGNUM calls behind key
  generation and JWK parameters, and EVP_DigestSign/Verify."
  (:require [jolt.ffi :as ffi]))

(ffi/defcfn c-rand     "RAND_bytes"          [:pointer :int] :int)
(ffi/defcfn c-aes128   "EVP_aes_128_cbc"     [] :pointer)
(ffi/defcfn c-aes192   "EVP_aes_192_cbc"     [] :pointer)
(ffi/defcfn c-aes256   "EVP_aes_256_cbc"     [] :pointer)
(ffi/defcfn c-md5      "EVP_md5"             [] :pointer)
(ffi/defcfn c-sha1     "EVP_sha1"            [] :pointer)
(ffi/defcfn c-sha224   "EVP_sha224"          [] :pointer)
(ffi/defcfn c-sha256   "EVP_sha256"          [] :pointer)
(ffi/defcfn c-sha384   "EVP_sha384"          [] :pointer)
(ffi/defcfn c-sha512   "EVP_sha512"          [] :pointer)
(ffi/defcfn c-ctx-new  "EVP_CIPHER_CTX_new"  [] :pointer)
(ffi/defcfn c-ctx-free "EVP_CIPHER_CTX_free" [:pointer] :void)
(ffi/defcfn c-enc-init "EVP_EncryptInit_ex"  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-enc-upd  "EVP_EncryptUpdate"   [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-enc-fin  "EVP_EncryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-dec-init "EVP_DecryptInit_ex"  [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dec-upd  "EVP_DecryptUpdate"   [:pointer :pointer :pointer :pointer :int] :int)
(ffi/defcfn c-dec-fin  "EVP_DecryptFinal_ex" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-hmac     "HMAC"   [:pointer :pointer :int :pointer :size_t :pointer :pointer] :pointer)
(ffi/defcfn c-digest   "EVP_Digest" [:pointer :size_t :pointer :pointer :pointer :pointer] :int)

;; EVP keys and ECDSA/RSASSA-PKCS1-v1_5. EVP_EC_gen is a macro rather
;; than an exported symbol, so EC keygen goes through EC_KEY and is then
;; wrapped in an EVP_PKEY for encoding and signing; RSA keygen goes through
;; RSA_new + RSA_generate_key_ex (EVP_PKEY_CTX-based RSA gen needs
;; EVP_PKEY_CTX_new_id, which is fine too but longer). i2d_*/d2i_* are the DER
;; codecs: i2d_PUBKEY is X.509 SubjectPublicKeyInfo (what PublicKey.getEncoded
;; returns) and EVP_PKEY2PKCS8 + i2d_PKCS8_PRIV_KEY_INFO is PKCS#8
;; PrivateKeyInfo (PrivateKey.getEncoded). d2i_AutoPrivateKey reads either
;; algorithm's PKCS#8, and the EVP_Digest* calls in pkey-sign/pkey-verify are
;; algorithm-agnostic — the algorithm is whatever the key is.
(ffi/defcfn c-ec-new-curve "EC_KEY_new_by_curve_name" [:int] :pointer)
(ffi/defcfn c-ec-gen       "EC_KEY_generate_key"      [:pointer] :int)
(ffi/defcfn c-ec-free      "EC_KEY_free"              [:pointer] :void)
(ffi/defcfn c-pkey-new     "EVP_PKEY_new"             [] :pointer)
(ffi/defcfn c-pkey-set-ec  "EVP_PKEY_set1_EC_KEY"     [:pointer :pointer] :int)
(ffi/defcfn c-pkey-free    "EVP_PKEY_free"            [:pointer] :void)
(ffi/defcfn c-i2d-pubkey   "i2d_PUBKEY"               [:pointer :pointer] :int)
(ffi/defcfn c-d2i-pubkey   "d2i_PUBKEY"               [:pointer :pointer :long] :pointer)
(ffi/defcfn c-pkey->p8     "EVP_PKEY2PKCS8"           [:pointer] :pointer)
(ffi/defcfn c-i2d-p8       "i2d_PKCS8_PRIV_KEY_INFO"  [:pointer :pointer] :int)
(ffi/defcfn c-p8-free      "PKCS8_PRIV_KEY_INFO_free" [:pointer] :void)
(ffi/defcfn c-d2i-privkey  "d2i_AutoPrivateKey"       [:pointer :pointer :long] :pointer)
(ffi/defcfn c-pem-read-privkey "PEM_read_bio_PrivateKey" [:pointer :pointer :pointer :pointer] :pointer)
(ffi/defcfn c-pem-read-pubkey  "PEM_read_bio_PUBKEY"     [:pointer :pointer :pointer :pointer] :pointer)
(ffi/defcfn c-md-ctx-new   "EVP_MD_CTX_new"           [] :pointer)
(ffi/defcfn c-md-ctx-free  "EVP_MD_CTX_free"          [:pointer] :void)
(ffi/defcfn c-dgst-sign-init   "EVP_DigestSignInit"   [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dgst-sign        "EVP_DigestSign"       [:pointer :pointer :pointer :pointer :size_t] :int)
(ffi/defcfn c-dgst-verify-init "EVP_DigestVerifyInit" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-dgst-verify      "EVP_DigestVerify"     [:pointer :pointer :size_t :pointer :size_t] :int)
(ffi/defcfn c-rsa-padding      "EVP_PKEY_CTX_set_rsa_padding" [:pointer :int] :int)
(ffi/defcfn c-rsa-pss-saltlen  "EVP_PKEY_CTX_set_rsa_pss_saltlen" [:pointer :int] :int)
(ffi/defcfn c-rsa-mgf1-md      "EVP_PKEY_CTX_set_rsa_mgf1_md" [:pointer :pointer] :int)

;; RSA keygen. RSA_generate_key_ex takes the public exponent as a BIGNUM, so a
;; BN_new/BN_set_word pair sets the usual 65537 (F4) before the call.
(ffi/defcfn c-rsa-new      "RSA_new"             [] :pointer)
(ffi/defcfn c-rsa-gen      "RSA_generate_key_ex" [:pointer :int :pointer :pointer] :int)
(ffi/defcfn c-rsa-free     "RSA_free"            [:pointer] :void)
(ffi/defcfn c-bn-new       "BN_new"              [] :pointer)
(ffi/defcfn c-bn-set-word  "BN_set_word"         [:pointer :ulong] :int)
(ffi/defcfn c-bn-free      "BN_free"             [:pointer] :void)
(ffi/defcfn c-pkey-set-rsa "EVP_PKEY_set1_RSA"   [:pointer :pointer] :int)

;; JWK parameter construction and inspection. BIGNUMs are copied into OpenSSL
;; keys, and every native key/point is released before the public byte/map value
;; is returned. RSA_set0_* transfers ownership only on success.
(ffi/defcfn c-bn-bin2bn       "BN_bin2bn"           [:pointer :int :pointer] :pointer)
(ffi/defcfn c-bn-bn2bin       "BN_bn2bin"           [:pointer :pointer] :int)
(ffi/defcfn c-bn-num-bits     "BN_num_bits"         [:pointer] :int)
(ffi/defcfn c-rsa-set0-key    "RSA_set0_key"        [:pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-rsa-set0-factors "RSA_set0_factors"   [:pointer :pointer :pointer] :int)
(ffi/defcfn c-rsa-set0-crt    "RSA_set0_crt_params" [:pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-rsa-get0-key    "RSA_get0_key"        [:pointer :pointer :pointer :pointer] :void)
(ffi/defcfn c-rsa-get0-factors "RSA_get0_factors"   [:pointer :pointer :pointer] :void)
(ffi/defcfn c-rsa-get0-crt    "RSA_get0_crt_params" [:pointer :pointer :pointer :pointer] :void)
(ffi/defcfn c-rsa-check       "RSA_check_key"       [:pointer] :int)
(ffi/defcfn c-pkey-get-rsa    "EVP_PKEY_get1_RSA"   [:pointer] :pointer)
(ffi/defcfn c-ec-set-private  "EC_KEY_set_private_key" [:pointer :pointer] :int)
(ffi/defcfn c-ec-set-public   "EC_KEY_set_public_key"  [:pointer :pointer] :int)
(ffi/defcfn c-ec-get0-group   "EC_KEY_get0_group"      [:pointer] :pointer)
(ffi/defcfn c-ec-get0-private "EC_KEY_get0_private_key" [:pointer] :pointer)
(ffi/defcfn c-ec-get0-public  "EC_KEY_get0_public_key"  [:pointer] :pointer)
(ffi/defcfn c-ec-check        "EC_KEY_check_key"       [:pointer] :int)
(ffi/defcfn c-ec-group-nid    "EC_GROUP_get_curve_name" [:pointer] :int)
(ffi/defcfn c-ec-point-new    "EC_POINT_new"          [:pointer] :pointer)
(ffi/defcfn c-ec-point-free   "EC_POINT_free"         [:pointer] :void)
(ffi/defcfn c-ec-point-set    "EC_POINT_set_affine_coordinates" [:pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-ec-point-mul    "EC_POINT_mul"          [:pointer :pointer :pointer :pointer :pointer :pointer] :int)
(ffi/defcfn c-ec-point-octets "EC_POINT_point2oct"    [:pointer :pointer :int :pointer :size_t :pointer] :size_t)
(ffi/defcfn c-pkey-get-ec     "EVP_PKEY_get1_EC_KEY"  [:pointer] :pointer)

;; Ed25519 keygen goes through an EVP_PKEY_CTX for the key type (NID 1087).
;; These are exported functions in both 1.1.1 and 3. Signing needs nothing
;; new: EVP_DigestSign/EVP_DigestVerify with a NULL digest are Ed25519's
;; one-shot (PureEdDSA) path.
(ffi/defcfn c-pkey-ctx-new-id  "EVP_PKEY_CTX_new_id"  [:int :pointer] :pointer)
(ffi/defcfn c-pkey-keygen-init "EVP_PKEY_keygen_init" [:pointer] :int)
(ffi/defcfn c-pkey-keygen      "EVP_PKEY_keygen"      [:pointer :pointer] :int)
(ffi/defcfn c-pkey-ctx-free    "EVP_PKEY_CTX_free"    [:pointer] :void)
(ffi/defcfn c-pkey-new-raw-private "EVP_PKEY_new_raw_private_key" [:int :pointer :pointer :size_t] :pointer)
(ffi/defcfn c-pkey-new-raw-public  "EVP_PKEY_new_raw_public_key"  [:int :pointer :pointer :size_t] :pointer)
(ffi/defcfn c-pkey-get-raw-private "EVP_PKEY_get_raw_private_key" [:pointer :pointer :pointer] :int)
(ffi/defcfn c-pkey-get-raw-public  "EVP_PKEY_get_raw_public_key"  [:pointer :pointer :pointer] :int)

(ffi/defcfn c-err-clear     "ERR_clear_error"      []         :void)
