# Katana + Raptor technical assessment

## 1. Executive summary

[EXECUTION] This execution-backed assessment used the dirty worktree at commit `8b51e6297661c9a653e1647c00f7f0738724bad3`; repository state and commands are preserved under `environment/`, `raw/`, and `evidence/`.

[REPOSITORY] Katana is an optional breadth pre-pass (`UseKatana=false` by default), and Raptor remains operational when both embedded and binary Katana paths fail.

[REPOSITORY] Chromium/CDP rows with `source_type=cdp_observed` and a CDP request ID are authoritative for confirmed HTTP requests; anchors, navigation seeds, static API candidates, and Katana URLs remain candidates.

[EXECUTION] Three validated local findings are normalized: SQL injection, verified reflected XSS, and a deterministic Nuclei exposure. LFImap emitted no scanner observation and therefore contributes no finding.

## 2. Scope and authorization

[EXECUTION] Active traffic was restricted to the assessment-owned `127.0.0.1:18080` Python fixture. Docker was not used because daemon access returned permission denied.

[EXECUTION] Scans used one worker/thread, short timeouts, a disposable cookie, and harmless in-memory data. No dump, enumeration, shell, file-write, callback, account-creation, DELETE, code, headless-template, or fuzz-template option was used.

## 3. Repository and environment versions

[EXECUTION] Go is 1.26.4, Python is 3.13.14, the kernel is Kali Linux 7.0.12, and Docker CLI is 28.5.2 while the daemon is unavailable.

[EXECUTION] Installed tools are Katana v1.6.1, SQLMap 1.10.6#stable, Dalfox v2.13.0, Nuclei v3.9.0, and LFImap package 0.1.4. Binary/script SHA-256 values are recorded in `environment/tool-hashes.txt`.

[EXECUTION] No `nuclei-templates` repository was installed, so a standard-template run and template commit pin were unavailable; only the hashed assessment template was run.

## 4. Current architecture

[REPOSITORY] CLI entry is `cmd/crawler/main.go:main`; it builds `CrawlerConfig`, creates a Chromium provider/session, calls `crawler.NewCrawlerWithBrowser`, then `Crawler.Run`. The localhost API entry is `cmd/raptor-api/main.go:main`, with lifecycle handling in `api/server.go:feed`, `run`, and `crawl`.

[REPOSITORY] `Crawler.Run` owns a priority queue. Katana seeds URLs, `StaticCrawler` adds HTML/JS/form candidates, and `DynamicCrawler` observes browser traffic. `Crawler.handleDiscovered` is the common persistence funnel and calls `RequestStore.SaveRequest`.

[REPOSITORY] `RequestStore.IndexRequest` calls `AnalyzeRequest`, writes `request_parameters`, `api_endpoint_inventory`, observations/aggregates, and only SQLMAP/DALFOX `scanner_candidates`. The downstream `ExportReplayArtifacts` creates SQLMap, Burp, Postman, HAR, and Dalfox artifacts.

[REPOSITORY] Major subsystem map:

| Subsystem | Source and symbols | Caller / consumer | Input / output | Failure modes / tests / gaps |
|---|---|---|---|---|
| CLI/config | `cmd/crawler/main.go:main,runCrawler`; `crawler/config.go:CrawlerConfig` | shell / `NewCrawlerWithBrowser` | flags -> config | missing seed is fatal; flags tested indirectly; no CLI auth credentials |
| Crawl API | `api/server.go:New,feed,run,crawl` | HTTP client / crawler DB | JSON feed -> crawl row and request views | API-key errors and row lookup; `api/server_test.go`; crawl association is added by worktree migration |
| Katana | `crawler/katana.go:RunKatanaPhase`; `katana_binary.go:RunKatanaBinary` | `Crawler.Run` / URL queue | seed/config -> URL seeds | embedded path always errors; PATH/output parsing failures; no dedicated Katana tests |
| Static discovery | `crawler/static.go:StaticCrawler.Crawl`; `jsparser.go` | queue / candidates and queue | URL response -> anchors/forms/scripts/API candidates | request/parse/scope failures; parser/application tests; candidates are not confirmations |
| Dynamic/CDP | `crawler/dynamic.go:DynamicCrawler.Start,Crawl,handleNetworkEvent` | queue / persistence funnel | browser events -> lifecycle request | body retrieval, correlation, drain and policy failures; extensive integration tests, two currently failing |
| Session/auth | `session/context.go:FileSession,ChromiumProvider,ApplyState,CaptureState`; dynamic auth helpers | CLI/session manager / browser context | state JSON -> cookies/storage/tokens | absent credentials and Chrome errors; session tests; CLI cannot supply `AuthConfig` |
| Persistence | `crawler/store.go:NewRequestStore,SaveRequest`; `api_intelligence.go:IndexRequest` | funnel / API/exporters | request -> SQLite normalized rows | best-effort ALTER migrations, transaction/index errors; intelligence tests; response status not present on raw row |
| Classification | `api_intelligence.go:EndpointTemplate,ClassifyObservedRequest,AnalyzeRequest` | IndexRequest / inventory and candidates | request -> class/template/schema/replay policy | heuristic misclassification; unit tests; auth context is coarse |
| Parameters | `extractParameters,flattenJSON,detectGraphQL` | AnalyzeRequest / request_parameters | query/path/body -> typed paths | multipart relies on form parsing and GraphQL on JSON shape; tests cover query/nested JSON/form sensitivity but not full multipart replay |
| Replay/export | `export.go:curatedReplayRows,replayText,exportDalfox` | CLI completion / scanners | inventory representative -> files | private/auth/mutation policy exclusions and write errors; export tests; Dalfox loses non-GET bodies |
| Coverage | `store.go` schema and `SaveCoverageGap` call sites | dynamic workflow / reporting | failure reason -> row | sparse producer coverage; empty in this run |

## 5. Katana assessment

[REPOSITORY] Katana is not mandatory. `RunKatanaPhase` deliberately returns `embedded katana engine disabled`; `Crawler.Run` then calls `RunKatanaBinary`, and logs/continues on failure.

[EXECUTION] Standard Katana v1.6.1 found the root, nine linked endpoints, the script, and the JS-derived `/api/profile?id=7`; it also extracted two POST forms as metadata. Headless mode captured the runtime fetch and candidate links but its JSONL contains candidate-only records without full responses for several links.

[EXECUTION] Raptor's first with-Katana pass demonstrated the absent-PATH fallback and completed with 20 Raptor requests. With `/home/b0y/go/bin` on PATH, Katana seeded 10 URLs and the combined run completed with the same 20 Raptor results in 11.82 seconds versus 0.07 seconds Raptor-only.

[INFERENCE] On this small linked fixture the pre-pass added latency but no final Raptor coverage; that result is fixture-specific and does not disprove breadth value on larger JS-heavy sites.

## 6. Raptor custom discovery assessment

[EXECUTION] Static Raptor found 20 candidate/result rows, all GET, including nine anchors and one script. It did not execute the POST form in static mode.

[EXECUTION] Authenticated dynamic Raptor produced 14 authoritative CDP rows (13 GET and one POST), plus nine anchor candidates and one navigation row. It executed the form-urlencoded form and observed the JS fetch.

[REPOSITORY] Static candidates remain distinguishable by `source_type` and absence of CDP/lifecycle evidence. They must not be promoted to `CONFIRMED_BROWSER_REQUEST`.

## 7. Katana/Raptor integration points

[REPOSITORY] Katana output is parsed by `parseKatanaJSONL`; `onDiscover` is intentionally nil in `Crawler.Run`, while `onSeed` enqueues in-scope normalized URLs. Raptor therefore owns request intelligence and persistence.

[REPOSITORY] Binary arguments omit configured Katana concurrency/field scope and use only URL, depth, JSONL, output, silent, optional headless/proxy. This makes CLI configuration partially ineffective.

## 8. Discovery coverage comparison

[EXECUTION] `normalized/coverage-matrix.csv` contains exact counts. Trust classes are `DISCOVERED_CANDIDATE` for Katana/static rows, `CONFIRMED_BROWSER_REQUEST` for CDP-completed rows, and `COVERAGE_GAP` for explicit failures.

[EXECUTION] Candidate/confirmed intersection includes the root, linked GET routes, script, and JS API route. The POST form is browser-confirmed but appears in Katana only as form metadata, not a confirmed POST request.

[EXECUTION] The authenticated pass classified every inventory row as `AUTHENTICATED` because the disposable cookie was applied globally; this does not mean every endpoint required authentication.

## 9. SQLMap

[REPOSITORY] The real adapter is `export.go:curatedReplayRows,replayText`, which writes raw HTTP requests and an index. It preserves method, Host, headers, cookies, and body, subject to safe/private/auth export policy and redaction.

[REPOSITORY] SQLMap mutates the explicit `-p` parameter and compares baselines using boolean, error, time, UNION, stacked, and inline families as allowed by level/risk/DBMS. It caches sessions under its output directory and `-r` replays raw requests.

[EXECUTION] Detection-only runs used `-r`, one `-p`, risk/level 1, one thread, 10-second timeout, one retry, traffic and HAR capture. SQLMap confirmed `id` twice using boolean, SQLite time-based, and one-column UNION techniques; the prepared control was not injectable.

[EXECUTION] JSON, form-urlencoded, and authenticated raw inputs were also exercised with boolean-only bounded checks and produced no finding. Installed SQLMap exposes no `--report-json` option, so that artifact is unavailable.

## 10. Dalfox

[REPOSITORY] `exportDalfox` supports eligible string query parameters on GET URLs only. It does not export POST, JSON, raw authenticated HTTP, or HAR input, causing material fidelity loss.

[REPOSITORY] Dalfox mines parameters, probes reflection characters, classifies injection context, generates context-aware payloads, and can use headless DOM verification. Installed v2.13.0 reports reflection (`R`) and verified (`V`) tiers in JSONL.

[EXECUTION] The analysis-only pass found `q` reflected with dangerous characters. The first active run yielded `R` only. The verification rerun yielded `V` with raw request/response evidence; the escaped endpoint yielded zero issues.

## 11. LFImap

[REPOSITORY] No LFImap adapter, candidate row, exporter, or invocation exists. The assessment therefore selected only `path` from the normalized inventory and created a separate marker-only corpus.

[EXECUTION] LFImap 0.1.4 ran `-t -q` with a three-entry marker wordlist, one parameter, 100 ms delay, and no `-x`, `-a`, RFI, command, wrapper, callback, or shell option. It sent three requests per continued case and reported zero vulnerabilities.

[EXECUTION] Exact marker replay returned the unique marker twice from the vulnerable endpoint and 404 from the constrained control. Because LFImap itself produced no positive observation, this is fixture validation rather than a normalized LFImap finding.

## 12. Nuclei

[REPOSITORY] No Nuclei adapter exists in Go code. README statements describe planned/claimed behavior without an implementation path.

[EXECUTION] No standard template repository was installed. The assessment custom template was validated and hashed; code, headless, and JavaScript template types were excluded, concurrency was one, and rate was two per second.

[EXECUTION] The custom HTTP template matched `/exposure` twice, stored request/response/report DB artifacts, and did not match `/no-exposure`. This satisfies scoped rerun validation.

## 13. Finding validation methodology

[REPOSITORY] Tool output is not platform confirmation. Normalized statuses are `UNVALIDATED`, `CONFIRMED`, `REJECTED_FALSE_POSITIVE`, `INCONCLUSIVE`, and `NOT_REPRODUCIBLE`.

[EXECUTION] Each confirmed normalized finding has a positive observation, repeat, control, exact input/output evidence, and tool version. SQLMap requires parameter/technique; Dalfox requires `V`; Nuclei requires rerun and matcher review.

## 14. Platform normalization model

[REPOSITORY] `normalized/scanner-runs.jsonl` and `normalized/findings.jsonl` implement the requested logical schemas and preserve raw plus normalized severity. Deduplication uses category, method, origin, endpoint template, parameter location/path, rule/technique, and auth context.

[REPOSITORY] `normalized/endpoint-inventory.jsonl` and `discovery-assets.jsonl` preserve candidate versus confirmed trust. `evidence.jsonl` mirrors hashed artifact provenance.

## 15. Scanner-selection rules

[REPOSITORY] Selection collapses to the inventory representative for method + origin + template + request schema + auth context. Static/framework traffic, OPTIONS, refresh, credentials/tokens, destructive DELETE, incomplete bodies, and semantic duplicates are excluded.

[EXECUTION] The run DB produced seven SQLMAP-eligible and four DALFOX-eligible rows. The observed POST body was stored as base64 text (`dGVybT10ZXN0`) while marked completeness unknown, and was not eligible.

## 16. Security and operational safeguards

[EXECUTION] All fixture state was in memory or a disposable cookie, the server bound only to loopback, and the LFI marker was synthetic. Commands and raw logs show prohibited options were absent.

[REPOSITORY] Export policy defaults to safe output and gates private/auth/mutation/destructive replay through environment flags. Private artifacts should retain mode 0600 and be excluded from ordinary bundles.

## 17. Confirmed defects and limitations

[EXECUTION] P0: browser POST `term=test` was persisted as base64 text with `body_complete=0`, `body_completeness_known=0`, yet inventory replayability was `REPLAYABLE_PRIVATE_AUTH`; body fidelity/completeness disagree.

[REPOSITORY] P0: `discovered_requests` has no response-status column; response/status aggregates were empty in the run, preventing requested response status normalization.

[EXECUTION] P1: a non-cached `go test ./...` failed `TestDynamicCrawlerPersistsRealLoginPOST` and `TestDynamicModalDrawerAndWizardFormsEnterQueueAndExecute` under default configuration.

[EXECUTION] P1: `go vet ./...` failed on unreachable code in `crawler/static.go:478`, consistent with the unconditional embedded-Katana return pattern elsewhere.

[EXECUTION] P1: Katana success depends on process PATH, and the initial enabled run silently degraded to Raptor-only. Embedded Katana is dead code after an unconditional return.

[REPOSITORY] P1: crawl ID is added by the API/worktree but CLI runs produced empty `crawl_id`; cross-run database association is incomplete.

[REPOSITORY] P2: LFImap/Nuclei have no adapters; Dalfox is GET-only; GraphQL and multipart extraction exist heuristically but lack end-to-end scanner replay evidence.

[EXECUTION] P2: standard Nuclei safe-template coverage was skipped because no pinned template repository existed.

## 18. Prioritized remediation roadmap

[RECOMMENDATION] P0 correctness/safety: decode CDP base64 bodies before analysis/export, make completeness authoritative, block incomplete bodies consistently, persist response status/request-response evidence, and add regression tests for form, JSON, multipart, and GraphQL fidelity.

[RECOMMENDATION] P0 correctness/safety: attach a generated crawl ID to every CLI/API row before observation and require it in inventory/scanner run foreign-key relationships.

[RECOMMENDATION] P1 integration reliability: remove unreachable embedded Katana code or repair it; resolve the binary explicitly at startup; pass all configured Katana flags; persist its command, version, exit code, and output path.

[RECOMMENDATION] P1 integration reliability: implement scanner-run/finding tables and an immutable corpus exporter; add actual LFImap/Nuclei adapters only after safe allowlists and template pins are defined.

[RECOMMENDATION] P2 coverage: add deterministic auth, JSON, multipart, GraphQL, DOM-XSS, and workflow fixtures; make credential configuration explicit in integration tests.

[RECOMMENDATION] P3 usability/reporting: expose trust class, exclusion reason, response status, duplicate key, template commit, and validation status through the localhost API.

## 19. Evidence index

[EXECUTION] `evidence-manifest.json` lists artifact path, SHA-256, producing command, tool/version, timestamp, target fixture, exit code, and redaction status. `normalized/evidence.jsonl` provides a line-oriented mirror.

## 20. Exact reproduction commands

[EXECUTION] Exact commands are embedded in each `script` log header and manifest. Primary forms were: standalone Katana `-d 2 -c 1 -p 1 -rl 5`; Raptor with and without `-katana`; SQLMap `-r ... -p id --batch --risk=1 --level=1 --threads=1`; Dalfox v2 `url ... -p q`; LFImap `-R ... -t -q -wT marker-wordlist`; and Nuclei `-t nuclei-raptor-exposure.yaml -ept headless,code,javascript -c 1 -rl 2`.

[EXECUTION] The lab starts with `python3 assessment/lab/server.py` and resets by stopping and restarting that process; it has no persistent mutable data.
