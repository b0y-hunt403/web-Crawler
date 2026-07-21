# crawler

Go package for `sessionmgr` — discovers pages, API endpoints, forms/inputs,
and SPA routes. No auth/session logic lives here; that's `session/`'s job.
This package only *reads* an already-captured session file
(`CrawlerConfig.SessionStatePath`).

## Latest fix — request body modeling (JSON forms)

Real problem observed: `/en/signin` and `/en/register` were being recorded
as **GET requests with credentials in the query string**
(`?password=Test1234!&username=testuser`) — wrong, and actively bad hygiene
to have sitting in `scanner.db`. Root cause: modern SPA forms (React/Next.js)
routinely omit or default `method`/`enctype` in markup and handle the real
submission in JS via `fetch()`/`axios()` with a JSON body — the markup gives
no visible sign of this, so guessing one representation from markup alone
is guaranteed to be wrong some of the time.

**Fix — `BuildFormSubmissions` (`classifier.go`)**: instead of picking one
guessed representation, the crawler now emits *every plausible* one:

- A form with an **explicit** `method="get"` and no password field → a real
  GET/query-string request (unambiguous, taken at face value).
- Everything else (no explicit method at all, explicit POST, or explicit
  `method="get"` *with* a password field — untrustworthy markup) becomes a
  set of POST candidates: a form-urlencoded guess (or multipart placeholder
  if `enctype="multipart/form-data"` was explicit) **and** a JSON guess,
  always both, each with its own fingerprint so neither is dropped.
- A password field **never** produces a GET/querystring variant, even if
  `method="get"` is explicitly declared in markup — that markup isn't
  trustworthy enough to justify writing live credentials into a stored URL.

Both `static.go` and `dynamic.go` (including shadow-DOM forms) now share
this single implementation instead of each having their own guessing logic.

**Also fixed — JSON bodies are now first-class, everywhere, not just for
form guesses.** `ExtractParameters` (`fingerprint.go`) now parses
`application/json` bodies into flattened, structured `Parameter` records
(`user.email`, `tags[0]`, etc.) — this applies to *real* JSON bodies
captured via network interception too (an actual `fetch()` call the app
made), not only the crawler's own form guesses. Every `DiscoveredRequest`
now also carries an explicit `BodyType` (`"json"`, `"form-urlencoded"`,
`"multipart"`, `"graphql"`, `"query"`, `"other"`, or `""`) so downstream
code switches on one clean field instead of re-sniffing `Content-Type`.
GraphQL bodies (`{"query": "...", "variables": {...}}`) are auto-detected
and tagged `"graphql"` even when the URL itself doesn't say "graphql".

`store.go` gained a `body_type` column (with a forward-migration for
existing `scanner.db` files).

## What changed in the prior round

### 🔴 Priority 1 — correctness bugs, all fixed

1. **The DOM-parsing crash that was silently eating pages.**
   Root cause: browsers expose named form controls as *direct properties*
   on their parent `<form>` element. A form with `<input name="name">`
   makes `form.name` return that `<input>` element, not the form's `name`
   attribute string (the same well-known quirk that lets
   `<input name="submit">` shadow `form.submit()`). The old extraction JS
   read `f.name`/`f.id`/`f.action` as bare properties — when a form had a
   field with one of those names, the JSON built in JS contained an object
   where Go expected a string, `json.Unmarshal` failed for the *entire
   page*, and every link/form/script on that page silently vanished. That's
   why dynamic crawl (84) undershot static (459) so badly.

   **Fix:** `domExtractionJS` in `dynamic.go` now reads every piece of
   form-level metadata via `getAttribute()`, never as a bare property.
   Attributes can't be shadowed by child controls. See the big comment
   directly above `domExtractionJS`.

2. **Duplicate URLs.** Dedup now happens by *fingerprint*
   (`method + normalized URL + sorted body + content-type`), not raw URL
   string, at the single funnel every discovery passes through
   (`Crawler.handleDiscovered`). `/`, `/`, `/` collapses to one entry.

3. **URL normalization.** `NormalizeURL` now also collapses duplicate
   slashes (`//`→`/`) on top of the existing fragment-stripping, trailing-
   slash-trimming, and default-port-stripping — so `/about`, `/about/`,
   and `/about#` are all one discovery.

4. **Depth calculation.** The seed URL itself was never recorded before —
   only *links back to it* were, which is why you saw `depth: 1` for `/`
   and never `depth: 0`. Both crawlers now record the page they actually
   visited at its own depth (not depth+1); everything discovered *on* that
   page is depth+1. Static crawler does this explicitly in `CrawlURL`;
   dynamic crawler does it by tagging the main-document network response
   at the current depth instead of depth+1 (see `trackRequest`).

### 🟠 Priority 2 — crawler intelligence

5. **JS endpoint extraction, expanded** (`jsparser.go`): now also matches
   `fetch()`, `axios(...)`/`axios.get/post/put/delete/patch()`,
   `XMLHttpRequest.open(method, url)`, `new URL(...)`, dynamic `import()`,
   hardcoded absolute URLs anywhere in the source, and a GraphQL heuristic
   that tags matches as `source_type: js_graphql_endpoint` instead of
   lumping them in with REST calls.
6. **Network request interception**: `dynamic.go` now listens for
   `network.EventRequestWillBeSent` *and* `EventResponseReceived`,
   correlating them by CDP `RequestID` into one `DiscoveredRequest` with
   the full request (method/headers/body) and response together, instead
   of only ever seeing what HTML parsing could infer.
7. **Response metadata**: every `DiscoveredRequest` can now carry a
   `Response` (`status_code`, `content_type`, `content_length`, `server`,
   `cache_control`, full headers, `Set-Cookie` values). Static crawler
   populates this from the real `http.Response`; dynamic crawler populates
   it from the correlated CDP response event.
8. **Better form modeling**: `Form` now includes `Enctype`,
   `CSRFTokenField` (auto-detected from common token names —
   `csrf_token`, `authenticity_token`, `_token`, etc.), and
   `RequiredFields`. CSRF fields are also flagged per-field
   (`FormField.IsCSRFToken`) and their real DOM value is preserved instead
   of being overwritten with a placeholder.

### 🟡 Priority 3 — architecture

9. **Request fingerprinting**: `CalculateFingerprint` now hashes
   `method + normalized URL + sorted body + content-type`, not just
   method+URL+raw-body — field order in a form no longer produces two
   fingerprints for the same logical submission.
10. **Canonical parameter storage**: every `DiscoveredRequest` carries
    `Parameters []Parameter` (`{name, value, in: "query"|"body"}`), sorted
    and structured — no more re-parsing `age=1&name=test` downstream.
11. **Priority queue**: `crawler.go` replaced the plain FIFO slice with a
    `container/heap`-based priority queue. URLs containing
    `login`/`signin`/`admin` get priority 0, `register`/`signup`/`/api/`/
    `graphql` get priority 1, everything else is 5 — so on a large site
    those surfaces get crawled well before `MaxPages` runs out, instead of
    being starved behind hundreds of marketing pages.
12. **robots.txt (optional)**: `CrawlerConfig.RespectRobotsTxt`, off by
    default. When on, fetches `/robots.txt` once and does simple
    prefix-based `Disallow` matching for `User-agent: *`. No wildcards,
    no crawl-delay — this is "enterprise mode", not a compliance engine.

## Compatibility with your existing main.go / main_colored.go

Nothing changes on your end. `main.go` calls `crawler.NewCrawler(config)` —
unchanged. `main_colored.go` calls
`crawler.NewCrawlerWithCallback(config, coloredCallback)` — this function
now exists (it didn't in the previous drop, which is why I'm calling it out
explicitly). Your callback fires for every discovery in addition to (not
instead of) persistence + dedup, so colored live output keeps working
exactly as written.

New optional config knobs, both default to today's behavior if unused:

```go
config.RespectRobotsTxt = true // off by default
```

## Still not build-verified

Same caveat as before: no Go toolchain in this sandbox, so this hasn't been
compiled. The changes are larger this round (chromedp event correlation,
container/heap) — please `go build ./...` and sanity-check against your
pinned `chromedp`/`cdproto` versions. Likely friction points:

- `network.EventResponseReceived.Response.Status` — I read this as
  `int64` and cast to `int`; some cdproto versions may already type it as
  a plain `int64` or `int`, adjust the cast if `go vet` complains.
- `network.ResourceTypeXHR` / `ResourceTypeFetch` / `ResourceTypeScript` /
  `ResourceTypeDocument` constant names — these are standard cdproto names
  but double-check against your pinned version.
- `chromedp.ProxyServer` — same note as last time, fall back to
  `chromedp.Flag("proxy-server", ...)` if it's missing.

## Dependencies (unchanged)

```
go get github.com/chromedp/chromedp
go get github.com/chromedp/cdproto
go get github.com/PuerkitoBio/goquery
go get modernc.org/sqlite
```
