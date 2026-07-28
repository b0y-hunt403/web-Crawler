# Raptor

<div align="center">
  <img src="images/banner.png" alt="Raptor web crawler" width="800">
</div>

<p align="center">
  <strong>A Go-based web reconnaissance crawler focused on request intelligence.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go" alt="Go 1.26+">
  <img src="https://img.shields.io/badge/storage-SQLite-003B57?logo=sqlite" alt="SQLite">
  <img src="https://img.shields.io/badge/browser-Chromium-4285F4?logo=googlechrome" alt="Chromium">
  <img src="https://img.shields.io/badge/discovery-Katana-7B42BC" alt="Katana">
</p>

Raptor combines fast URL discovery with static analysis and Chromium-backed
dynamic crawling. Katana is used to find URLs; Raptor owns request capture,
normalization, authentication metadata, form analysis, JavaScript endpoint
extraction, deduplication, and SQLite persistence.

> Use Raptor only against systems you own or are explicitly authorized to test.

## Status

Raptor is under active development. The current implementation supports:

- Static HTML crawling and form extraction
- Chromium network capture through `chromedp`
- Optional Katana URL-discovery pre-pass
- GET, POST, PUT, PATCH and other browser-observed requests
- JSON, URL-encoded, multipart, GraphQL, XML and text content classification
- Request headers, cookies, authorization and CSRF metadata
- JavaScript endpoint and SPA route extraction
- Authenticated form and JSON login workflows
- Browser cookie, localStorage and sessionStorage reuse
- Automatic authentication refresh after an expired session is detected
- SQLite persistence and JSON crawl output

Dedicated Postman, Burp, SQLMap request-file, Nuclei and ffuf exporters are
planned. The current scanner integration examples use SQLite queries and the
authenticated cookie export.

## Architecture

```text
                         +---------------------+
                         |       Katana        |
                         | URL discovery only  |
                         +----------+----------+
                                    |
                                    v
+------------------+      +---------+----------+
| Static crawler   +----->| Priority URL queue |
| HTML and forms   |      +---------+----------+
+------------------+                |
                                    v
                         +----------+-----------+
                         | Chromium / chromedp  |
                         | DOM + network events |
                         +----------+-----------+
                                    |
                                    v
                         +----------+-----------+
                         | Request intelligence |
                         | normalize / classify |
                         | enrich / deduplicate |
                         +----------+-----------+
                                    |
                                    v
                         +----------+-----------+
                         |       SQLite         |
                         | discovered_requests  |
                         | auth metadata        |
                         +----------------------+
```

Katana results are used to seed Raptor's crawl queue. Katana request records are
not treated as authoritative request intelligence.

## Requirements

- Go 1.26 or newer
- Chromium or Google Chrome for dynamic and authenticated crawling
- SQLite CLI, optional, for inspecting databases
- Linux, macOS or Windows

The Katana Go library is included through Go modules. Raptor can also fall back
to a Katana binary when available.

## Installation

Clone and build:

```bash
git clone https://github.com/Anduamlk/web-Crawler.git
cd web-Crawler
go mod download
go build -o raptor ./cmd/crawler
```

Verify the installation:

```bash
./raptor -help
```

Run the test suite:

```bash
go test ./...
go vet ./...
```

## Quick start

Static crawl:

```bash
./raptor \
  -url https://target.example \
  -db results.db \
  -depth 3 \
  -pages 100
```

Dynamic crawl for JavaScript-heavy applications:

```bash
./raptor \
  -url https://target.example \
  -db results.db \
  -dynamic \
  -depth 3 \
  -pages 100
```

Run the static and dynamic phases:

```bash
./raptor \
  -url https://target.example \
  -db results.db \
  -both
```

Use Katana for breadth-first URL discovery:

```bash
./raptor \
  -url https://target.example \
  -db results.db \
  -both \
  -katana \
  -katana-depth 3 \
  -katana-concurrency 20
```

Write crawl results to JSON in addition to SQLite:

```bash
./raptor \
  -url https://target.example \
  -db results.db \
  -dynamic \
  -output results.json
```

## Authenticated crawling

Supplying `-username`, `-password`, and `-login-url` automatically enables the
browser crawler. Raptor logs in before crawling and reuses the same browser
context for subsequent pages.

### HTML form login

```bash
./raptor \
  -url https://target.example/app \
  -login-url https://target.example/login \
  -username analyst@example.com \
  -password 'replace-me' \
  -login-method form \
  -session-cookie session \
  -cookie-file raptor-session.json \
  -db authenticated.db
```

Raptor attempts to detect username, password and CSRF inputs automatically.
Field names, element IDs or CSS selectors can be supplied when detection is
ambiguous:

```bash
./raptor \
  -url https://target.example/app \
  -login-url https://target.example/sign-in \
  -username analyst@example.com \
  -password 'replace-me' \
  -username-field '#email' \
  -password-field '#password' \
  -csrf-field '_csrf' \
  -login-method form \
  -db authenticated.db
```

### JSON login

```bash
./raptor \
  -url https://target.example/app \
  -login-url https://target.example/api/login \
  -username analyst@example.com \
  -password 'replace-me' \
  -username-field email \
  -password-field password \
  -login-method json \
  -session-cookie access_token \
  -cookie-file raptor-session.json \
  -db authenticated.db
```

### Login success detection

Raptor recognizes successful authentication through:

- A URL change
- A logout control
- A dashboard or account redirect
- Creation of a new cookie
- Creation of the configured session cookie
- An optional success regex

Example:

```bash
./raptor \
  -url https://target.example/app \
  -login-url https://target.example/login \
  -username analyst@example.com \
  -password 'replace-me' \
  -login-success-regex 'Welcome|/dashboard' \
  -db authenticated.db
```

The cookie export is written with owner-only permissions and contains the cookie
header plus command hints for SQLMap, Dalfox, Nuclei, ffuf and httpx.

> Command-line passwords may be recorded in shell history or process listings.
> Use a protected launcher or secret-injection mechanism for real credentials.

## Reusing an existing session

Raptor accepts a browser storage-state JSON file:

```bash
./raptor \
  -url https://target.example/app \
  -session session.json \
  -dynamic \
  -db results.db
```

The state format contains browser cookies and origin-scoped localStorage values.

## Proxying traffic

Send browser traffic through an HTTP proxy such as Burp Suite or ZAP:

```bash
./raptor \
  -url https://target.example \
  -dynamic \
  -proxy http://127.0.0.1:8080 \
  -db proxied.db
```

## Important options

| Option | Default | Description |
|---|---:|---|
| `-url` | required | Seed URL |
| `-db` | `scanner_discovery.db` | SQLite database path |
| `-depth` | `3` | Maximum crawl depth |
| `-pages` | `100` | Maximum pages |
| `-concurrency` | `5` | Requested crawler concurrency |
| `-timeout` | `30s` | Request/navigation timeout |
| `-dynamic` | `false` | Enable Chromium crawling |
| `-both` | `false` | Run static and dynamic phases |
| `-stay-in-domain` | `true` | Restrict crawling to the seed host |
| `-katana` | `false` | Enable the Katana discovery pre-pass |
| `-katana-depth` | `2` | Katana crawl depth |
| `-katana-concurrency` | `20` | Katana worker count |
| `-proxy` | empty | HTTP proxy URL |
| `-session` | empty | Existing browser state file |
| `-output` | empty | Optional JSON result file |
| `-username` | empty | Login username |
| `-password` | empty | Login password |
| `-login-url` | empty | Login page or API endpoint |
| `-login-method` | `form` | `form` or `json` |
| `-username-field` | auto | Field name, ID or selector |
| `-password-field` | auto | Field name, ID or selector |
| `-csrf-field` | auto | CSRF field, selector or JSON header |
| `-session-cookie` | auto | Cookie used to confirm login |
| `-login-success-regex` | empty | URL/page-text success expression |
| `-cookie-file` | empty | Authenticated session export |

Run `./raptor -help` for the complete list.

## SQLite output

The primary compatibility table is `discovered_requests`.

Important columns include:

| Column | Description |
|---|---|
| `id` | Semantic request fingerprint |
| `auth_session_id` | Associated authentication session |
| `method` | HTTP method |
| `url` | Original URL |
| `normalized_url` | Canonical URL |
| `headers` | Request headers as JSON |
| `cookies` | Parsed request cookies as JSON |
| `parameters` | Query/form parameters as JSON |
| `body` | Raw request body |
| `body_type` | JSON, form, multipart, XML, text or binary classification |
| `response` | Response metadata as JSON |
| `source_type` | Browser, page, form or JavaScript discovery source |
| `depth` | Crawl depth |
| `created_at` | UTC discovery time |

Authentication metadata is stored separately in:

- `auth_sessions`
- `login_requests`
- `cookies`
- `csrf_tokens`

### Useful queries

Request counts by method and source:

```bash
sqlite3 results.db "
SELECT method, source_type, COUNT(*) AS total
FROM discovered_requests
GROUP BY method, source_type
ORDER BY total DESC;
"
```

Pretty-print headers containing cookies:

```bash
sqlite3 -header -column results.db "
SELECT
  method,
  url,
  json_extract(headers, '$.Cookie') AS cookie
FROM discovered_requests
WHERE json_extract(headers, '$.Cookie') IS NOT NULL;
"
```

Find browser-observed POST requests:

```bash
sqlite3 -header -column results.db "
SELECT url, body_type, body
FROM discovered_requests
WHERE method = 'POST'
  AND source_type IN ('ajax_fetch', 'login_request');
"
```

Find JSON requests:

```bash
sqlite3 -header -column results.db "
SELECT
  method,
  url,
  json_extract(json_format, '$.payload') AS payload
FROM discovered_requests
WHERE json_extract(json_format, '$.is_json') = 1;
"
```

Find GraphQL candidates:

```bash
sqlite3 -header -column results.db "
SELECT method, url, body
FROM discovered_requests
WHERE source_type = 'graphql'
   OR lower(url) LIKE '%graphql%'
   OR lower(body) LIKE '%mutation%';
"
```

## Scanner workflows

### SQLMap

Export parameterized GET URLs:

```bash
sqlite3 -noheader results.db "
SELECT DISTINCT url
FROM discovered_requests
WHERE method = 'GET' AND instr(url, '?') > 0;
" > sqlmap-urls.txt

sqlmap -m sqlmap-urls.txt --batch
```

Authenticated scans can reuse the cookie header from `raptor-session.json`.
For POST and JSON requests, a dedicated raw HTTP request exporter is planned.

### Dalfox

```bash
sqlite3 -noheader results.db "
SELECT DISTINCT url
FROM discovered_requests
WHERE method = 'GET' AND instr(url, '?') > 0;
" > dalfox-urls.txt

dalfox file dalfox-urls.txt
```

### Nuclei, ffuf and httpx

The authenticated cookie export includes command hints for these tools.
Request-specific adapters and template generation are on the roadmap.

## Request normalization

Raptor currently normalizes:

- URL scheme and hostname case
- Default HTTP and HTTPS ports
- URL fragments
- Trailing slashes
- Query parameter ordering
- JSON object formatting for fingerprints
- URL-encoded form ordering
- Content-Type parameters for semantic comparison

The raw URL, headers and body remain available for debugging and replay.

## JavaScript intelligence

Raptor analyzes loaded JavaScript for:

- REST-style endpoints
- `fetch(...)`
- Axios requests
- `XMLHttpRequest.open(...)`
- GraphQL endpoints and operations
- WebSocket URLs
- EventSource endpoints
- Beacon calls
- React and Vue route definitions
- Dynamically imported routes

JavaScript extraction is heuristic. Browser-observed network requests should be
treated as higher-confidence evidence than statically inferred endpoints.

## Roadmap

- Versioned request-schema migrations
- Human-readable database viewer
- Canonical structured `requests` table
- Raw HTTP replay export
- curl export
- Postman Collection v2.1 export
- SQLMap request-file adapter
- Dalfox input adapter
- Nuclei request/template adapter
- ffuf command generation
- Response-body capture with configurable limits
- AST-backed JavaScript analysis
- Multi-step and MFA-assisted authentication workflows

## Project layout

```text
cmd/crawler/        Raptor command-line application
cmd/sessionmgr/     Session recording and verification utility
crawler/            Crawl, browser, request-intelligence and SQLite code
session/            Session archive and replay support
images/             Project artwork
```

## Security and data handling

Crawler databases and session exports may contain:

- Passwords submitted to test forms
- Session cookies
- Authorization headers
- CSRF tokens
- Personal or application data

Do not commit generated databases, session exports or credential files. Store
them securely, restrict filesystem permissions and delete them when no longer
needed.

## Contributing

1. Create a focused branch.
2. Keep changes backward compatible with `discovered_requests`.
3. Add tests for normalization, persistence and request capture behavior.
4. Run:

   ```bash
   gofmt -w $(find cmd crawler session -name '*.go')
   go test ./...
   go vet ./...
   ```

5. Open a pull request describing the behavior change and migration impact.

Bug reports should include the Raptor command, target application type, relevant
logs and a sanitized database example. Never include live credentials or tokens.
