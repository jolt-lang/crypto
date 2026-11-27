;; metrics-gate.clj — fail the build on what ci/metrics-allow.edn rules out:
;;
;;   jolt ci/metrics-gate.clj <report.edn> <ci/metrics-allow.edn>
;;
;; The report is jolt-metrics' --format edn output. Three checks:
;;
;; * Critical findings. Under each path prefix in :critical-free, any CRITICAL
;;   finding in the refactoring queue fails the gate (a function past a hard
;;   complexity, length, nesting or parameter limit, or a file past the file
;;   length limit), and so does a file jolt-metrics could not read, since it
;;   went unscored. The one exception is a :criticals entry, which names a
;;   finding that predates the gate by path and name and records the value of
;;   each rule it breaks in :limits. It passes while no rule gets worse than
;;   recorded and no new rule goes critical. An entry whose finding is no longer
;;   critical fails as stale, so it's removed once the code is fixed, unless it
;;   records only :hotspot: hotspot risk follows churn, so such an entry's
;;   finding comes and goes with the calendar.
;;
;; * Unused code. The allowlist names each unused require, unused private
;;   function and unreferenced public function that stays on purpose, with the
;;   reason: a caller the tool can't see (a var-deref from Scheme, a #' lookup),
;;   a deliberate re-export, upstream code kept as written. A finding not on it
;;   fails the gate, and so does an entry that no longer matches a finding, so
;;   the list can't go stale.
;;
;; * Lint findings. An :error lint always fails. A :warning lint, and a
;;   performance-rule lint at any level, fails unless :lints in the allowlist
;;   covers it. An entry names a path, a rule and how many findings of that rule
;;   the file keeps, so it survives lines moving but not a new finding; a count
;;   that no longer matches fails either way. Other :info lints are reported
;;   but don't gate. Findings an ignore marker or a .jolt-metrics.edn :linters
;;   level leaves out never reach the report, so they need no entry.
;;
;; Every allowlist entry needs a :why.
;;
;; Copied from jolt-lang/jolt's ci/metrics-gate.clj at 3f950626, with the
;; :criticals allowlist added.
(require '[clojure.edn :as edn]
         '[clojure.string :as str])

(def ^:private perf-rules
  "jolt-metrics' performance rules: each one is needless work, so it gates at
  whatever level the config gives it."
  #{:str-accumulation :concat-accumulation :contains-on-sequential
    :linear-membership :copying-pop :last-on-vector :lazy-into})

(defn- finding-key [kind f]
  (case kind
    :unused-requires [(:path f) (:lib f)]
    (:unused-private :unused-public) [(:path f) (:name f)]
    :lints [(:path f) (:rule f)]))

(defn- under? [prefixes path]
  (some #(str/starts-with? path %) prefixes))

(defn- worse?
  "Whether a critical value is past what its :criticals entry recorded. A
  lower maintainability index is worse; for every other rule a higher value is."
  [rule value recorded]
  (if (= :maintainability rule) (< value recorded) (> value recorded)))

(defn- allowed-critical-problems
  "What an allowlisted critical finding breaks beyond its entry's :limits."
  [f entry]
  (for [v (:violations f)
        :when (= :critical (:band v))
        :let [recorded (get (:limits entry) (:rule v))]
        :when (or (nil? recorded) (worse? (:rule v) (:value v) recorded))]
    (str "critical " (name (:kind f)) " " (:path f) ":" (:line f) " " (:name f) " — "
         (name (:rule v)) " " (:value v)
         (if recorded
           (str " is worse than the " recorded " its :criticals entry records")
           (str " > " (:limit v) " is critical, and its :criticals entry doesn't record "
                (name (:rule v))))
         "; fix it rather than raising the entry")))

(defn- churn-only?
  "Whether a :criticals entry records only hotspot risk, which rises and falls
  with recent churn rather than with the code."
  [entry]
  (= #{:hotspot} (set (keys (:limits entry)))))

(defn- critical-problems [report allow allow-path]
  (let [prefixes (:critical-free allow)
        criticals (filter #(and (= :critical (:severity %)) (under? prefixes (:path %)))
                          (:queue report))
        allowed (into {} (map (fn [a] [[(:path a) (:name a)] a]) (:criticals allow)))
        found (set (map (juxt :path :name) criticals))]
    (concat
     (for [f criticals
           :let [entry (get allowed [(:path f) (:name f)])]
           p (if entry
               (allowed-critical-problems f entry)
               [(str "critical " (name (:kind f)) " " (:path f) ":" (:line f) " " (:name f) " — "
                     (str/join ", " (for [v (:violations f) :when (= :critical (:band v))]
                                      (str (name (:rule v)) " " (:value v) " > " (:limit v)))))])]
       p)
     (for [[k entry] (sort-by key allowed)
           :when (not (or (contains? found k) (churn-only? entry)))]
       (str "stale :criticals entry " (pr-str k)
            " — it is no longer critical; remove it from " allow-path))
     (for [e (:errors report) :when (under? prefixes (:path e))]
       (str "unreadable " (:path e) " — " (:error e))))))

(defn- unused-problems [cleanup allow allow-path]
  (for [kind [:unused-requires :unused-private :unused-public]
        :let [found   (into {} (map (fn [f] [(finding-key kind f) f]) (get cleanup kind)))
              allowed (into {} (map (fn [a] [(finding-key kind a) a]) (get allow kind)))]
        p (concat
           (for [[k f] (sort-by key found) :when (not (contains? allowed k))]
             (str "new " (name kind) ": " (pr-str (dissoc f :line))
                  " — remove it, or add it to " allow-path " with the reason it stays"))
           (for [[k _] (sort-by key allowed) :when (not (contains? found k))]
             (str "stale " (name kind) " entry " (pr-str k)
                  " — it is no longer reported; remove it from " allow-path)))]
    p))

(defn- gated? [l]
  (and (not= :error (:level l))
       (or (= :warning (:level l)) (contains? perf-rules (:rule l)))))

(defn- lint-line [l]
  (str (:path l) ":" (:line l) ":" (:column l) " " (name (:level l)) " "
       (name (:rule l)) " — " (:message l)))

(defn- lint-problems [lints allow allow-path]
  (let [found (group-by #(finding-key :lints %) (filter gated? lints))
        allowed (into {} (map (fn [a] [(finding-key :lints a) a]) (:lints allow)))]
    (concat
     (for [l lints :when (= :error (:level l))]
       (str "lint " (lint-line l) " — an error can't be allowlisted; fix it"))
     (for [[k ls] (sort-by key found)
           :let [n (count ls) a (get allowed k)]
           :when (not= n (:count a))
           p (if (and a (< (:count a) n))
               [(str "lint " (pr-str k) ": " n " found, " allow-path " allows " (:count a)
                     " — fix the new one(s), or raise :count with the reason")]
               (if a
                 [(str "stale lint entry " (pr-str k) ": " n " found, " allow-path
                       " allows " (:count a) " — lower its :count to " n)]
                 (for [l (sort-by :line ls)]
                   (str "lint " (lint-line l) " — fix it, or add {:path " (pr-str (:path l))
                        " :rule " (:rule l) " :count " n " :why ...} to " allow-path))))]
       p)
     (for [[k _] (sort-by key allowed) :when (not (contains? found k))]
       (str "stale lint entry " (pr-str k)
            (if (some #(and (= :error (:level %)) (= k (finding-key :lints %))) lints)
              " — :error findings can't be allowlisted; remove it from "
              " — it is no longer reported; remove it from ")
            allow-path)))))

(defn- why-problems [allow allow-path]
  (for [kind [:criticals :unused-requires :unused-private :unused-public :lints]
        a (get allow kind)
        :when (str/blank? (:why a))]
    (str kind " entry " (pr-str a) " in " allow-path " has no :why")))

(defn -main [report-path allow-path]
  (let [report (edn/read-string (slurp report-path))
        allow (edn/read-string (slurp allow-path))
        lints (:lints report)
        problems (concat (why-problems allow allow-path)
                         (critical-problems report allow allow-path)
                         (unused-problems (:cleanup report) allow allow-path)
                         (lint-problems lints allow allow-path))]
    (doseq [p problems] (println p))
    (if (seq problems)
      (do (println (str "metrics gate: " (count problems) " problem(s)")) (System/exit 1))
      (println (str "metrics gate: no critical findings under "
                    (str/join ", " (:critical-free allow))
                    " beyond the " (count (:criticals allow)) " allowlisted"
                    ", no unused code or gated lint findings beyond the allowlist ("
                    (count (filter gated? lints)) " allowlisted lint findings, "
                    (count (remove gated? lints)) " ungated :info)")))))

(apply -main *command-line-args*)
