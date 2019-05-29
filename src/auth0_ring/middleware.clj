(ns auth0-ring.middleware
  (:require [auth0-ring.core :refer [delete-cookie]]
            [auth0-ring.jwt :refer [verify-token]]
            [clojure.data.json :as json]
            [clojure.tools.logging :as log]
            [clojure.walk :refer [keywordize-keys]]))

(defn wrap-token-verification [handler config]
  (fn [req]
    (let [id-token (get-in req [:cookies "id-token" :value])
          access-token (get-in req [:cookies "access-token" :value])]
      (if id-token
        (try
          (do
            (def user (verify-token config id-token))
            (if user
              (handler (assoc req :user (json/read-str user :key-fn keyword)))
              (update-in (handler req) [:cookies] #(merge {"id-token" (delete-cookie req)
                                                           "access-token" (delete-cookie req)} %))
              )
            )
          (catch Exception e
            (.printStackTrace e)
            (update-in (handler req) [:cookies] #(merge {"id-token" (delete-cookie req)
                                                         "access-token" (delete-cookie req)} %))
            )
          )
        (handler req)))))
