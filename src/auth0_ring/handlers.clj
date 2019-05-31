(ns auth0-ring.handlers
  (:require [auth0-ring.core :refer [qualify-url get-logout-url http-only-cookie delete-cookie]]
            [auth0-ring.jwt :refer [verify-token]]
            [clojure.string :as s]
            [clj-http.client :as http]
            [ring.util.codec :as codec]
            [clojure.tools.logging :as log]
            [clojure.data.json :as json])
  (:import [com.auth0 RandomStorage AuthenticationController]
           [org.apache.commons.codec.binary Base64]
           [java.security SecureRandom]))

(defn query-param [req p]
  (get (:query-params req) (name p)))

(defn parse-query-param [str param]
  (get (codec/form-decode str) (name param))
  )

(defn matches-nonce [req]
  (let [state (query-param req :state)
        nonce (get-in req [:cookies "nonce" :value])]
    (if nonce
      (and state (= (parse-query-param state :nonce) nonce))
      true)))

(defn is-valid [req]
  (and (not (query-param req :error))
       (matches-nonce req)))

(defn secureRandomString []
  (let [sr (new SecureRandom)
        randomBytes (byte-array 32)]
    (.nextBytes sr randomBytes)
    (Base64/encodeBase64URLSafeString randomBytes)
    )
  )

(defn redirect-uri [req redirect-path]
  (if (re-find #"^https?://" redirect-path)
    redirect-path
    (qualify-url req redirect-path)))

(defn get-url-path [url-str]
  (second (re-find #"(?:.+://[^/]+)?(.*)" url-str)))

;; (defn get-success-redirect [req config]
;;   (if-let [return-url (parse-query-param (query-param req :state) :returnUrl)]
;;     (qualify-url req (get-url-path return-url))
;;     (:success-redirect config)))

(defn query-string-to-map [query-string]
  (->> (s/split query-string #"&")
     (map #(s/split % #"="))
     (map (fn [[k v]] [(keyword k) v]))
     (into {})))

(defn exchange-code [config & [{:keys [query-string]} :as req]]
  (let [code (:code (query-string-to-map query-string))
        client-id (:client-id config)
        client-secret (:client-secret config)
        redirect-uri (str (:base config) (:callback-path config))]
    (log/info "TOKEN EXCHANGE" code config)
    (def tokens
      (:body (http/post (str "https://" (:domain config) "/oauth/token")
                        {:headers {"content-type" "application/x-www-form-urlencoded"}
                         :form-params {:grant_type "authorization_code"
                                       :client_id client-id
                                       :client_secret client-secret
                                       :code code
                                       :redirect_uri redirect-uri}})))
    (json/read-str tokens :key-fn keyword)))

(defn create-callback-handler [config & [{:keys [on-authenticated cookie-opts]
                                          :or {cookie-opts {}}}]]
  (fn [req]
    ;;(log/info "CALLBACK " req)
    (try
      (if (is-valid req)
        (let [tokens (exchange-code config req)
              user-profile (:id_token tokens)]
          (when (fn? on-authenticated)
            (on-authenticated user-profile tokens))
          (verify-token config (:id_token tokens))
          {:status 302
           :headers {"Location" (:success-redirect config)} ;;(get-success-redirect req config)}
           :cookies {"nonce" (delete-cookie req)
                     "id-token" (http-only-cookie req (merge
                                                       cookie-opts
                                                       {:value (:id_token tokens)}))
                     "access-token" (http-only-cookie req (merge
                                                           cookie-opts
                                                           {:value (:access_token tokens)}))}})
        {:status 302 :headers {"Location" (:error-redirect config)}})
      (catch RuntimeException e
        (.printStackTrace e)
        {:status 302 :headers {"Location" (:error-redirect config)}}))))



(defn create-logout-callback-handler [config]
  (fn [req]
    {:status 302
     :cookies {"id-token" (delete-cookie req)
               "access-token" (delete-cookie req)}
     :headers {"Location" (:logout-redirect config)}}))

(defn rand-str [len]
(apply str (take len (repeatedly #(char (+ (rand 26) 65))))))

(defn get-nonce [req]
  (let [cookie (:value (get (:cookies req) "nonce"))]
    (if (s/blank? cookie)
      (secureRandomString)
      cookie)))

(defn wrap-login-handler [handler]
  (fn [req]
    (let [nonce (get-nonce req)]
      ;;(log/info "NONCE " nonce)
      (assoc-in (handler (assoc req :nonce nonce))
                [:cookies "nonce"]
                (http-only-cookie req {:value nonce :max-age 600})))))

(defn create-logout-handler [config]
  (fn [req] {:status 302 :headers {"Location" (get-logout-url req config)}}))
