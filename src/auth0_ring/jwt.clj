(ns auth0-ring.jwt
  (:require [clojure.java.io :as io]
            [clojure.tools.logging :as log])
  (:import [com.auth0.jwk UrlJwkProvider]
           [com.auth0.jwt JWT JWTVerifier]
           [com.auth0.jwt.algorithms Algorithm]
           [java.util Base64]))

(defn decode [to-decode]
  (String. (.decode (Base64/getDecoder) to-decode)))

(defmulti get-jwt-verifier :signing-algorithm)

(defmethod get-jwt-verifier :hs256 [{:keys [client-secret client-id issuer]}]
  nil
  )

(defmethod get-jwt-verifier :rs256 [{:keys [public-key-path client-id issuer]}]
  nil
  )

(defn verify-token [config token]
  (let [jwt (JWT/decode token)
        provider (new UrlJwkProvider (str "https://" (:domain config) "/.well-known/jwks.json"))
        public-key (.getPublicKey (.get provider (.getKeyId jwt)))
        algorithm (Algorithm/RSA256 public-key)]
    (try
      (def verified-payload (decode (.getPayload (.verify (.build (.withAudience (.withIssuer (JWT/require algorithm) (into-array String [(:issuer config)]) ) (into-array String [(:client-id config)]))) token))))
      ;;(log/info verified-payload)
      verified-payload
      (catch RuntimeException e
        (.printStackTrace e)
        false))))
