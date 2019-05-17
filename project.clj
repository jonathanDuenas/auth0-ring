(defproject org.clojars.jduenas/auth0-ring "0.4.6"
  :description "Auth0 integration from Clojure"
  :url "http://github.com/jonathanDuenas/auth0-ring"
  :license {:name "BSD-3-Clause"
            :url "http://opensource.org/licenses/BSD-3-Clause"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [com.auth0/mvc-auth-commons "1.0.6"]
                 [com.auth0/jwks-rsa "0.8.1"]
                 [clj-http "3.10.0"]
                 [org.clojure/tools.logging "0.4.1"]
                 [org.clojure/data.json "0.2.6"]]
  :profiles {:dev {:dependencies [[ring "1.7.1"]]
                   :resource-paths ["resources-dev"]}})
