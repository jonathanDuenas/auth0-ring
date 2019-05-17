(ns auth0-ring.middleware
  (:require [auth0-ring.core :refer [delete-cookie]]
            [auth0-ring.jwt :refer [verify-token]]
            [clojure.data.json :as json]
            [clojure.walk :refer [keywordize-keys]]))

(defn wrap-token-verification [handler config]
  (fn [req]
    (let [id-token (get-in req [:cookies "id-token" :value])
          access-token (get-in req [:cookies "access-token" :value])]
      (if id-token
        (try
          (if-let [user (verify-token config id-token)]
            (handler (assoc req :user (json/read-str user :key-fn keyword)))
            (update-in (handler req) [:cookies] #(merge {"id-token" (delete-cookie req)
                                                         "access-token" (delete-cookie req)} %)))
          (catch RuntimeException e
;;            (.printStackTrace e)
            (update-in (handler req) [:cookies] #(merge {"id-token" (delete-cookie req)
                                                         "access-token" (delete-cookie req)} %))
            )
          )
        (handler req)))))
