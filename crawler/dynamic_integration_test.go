package crawler

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	sessionmgr "github.com/Anduamlk/web-Crawler/session"
)

func isChromeUnavailable(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return (strings.Contains(s, "chrome") || strings.Contains(s, "chromium")) && (strings.Contains(s, "not found") || strings.Contains(s, "executable") || strings.Contains(s, "sandbox") || strings.Contains(s, "launch"))
}

func TestDynamicCrawlerPersistsRealLoginPOST(t *testing.T) {
	var mu sync.Mutex
	var received string
	receivedMethod, receivedContentType := "", ""
	receivedCount := 0
	type receivedRequest struct{ method, contentType, body string }
	var receivedRequests []receivedRequest
	postReceived := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<form><input name="email" type="email" required><input name="password" type="password" required><input type="checkbox" name="remember"><button type="submit" disabled>Login</button></form><script>const state={email:'',password:''},form=document.querySelector('form'),button=form.querySelector('button');form.querySelectorAll('input').forEach(input=>input.addEventListener('input',()=>{if(input.name)state[input.name]=input.value;button.disabled=!(state.email&&state.password)}));form.addEventListener('submit',async e=>{e.preventDefault();await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:state.email,password:state.password})})})</script>`))
			return
		}
		if r.URL.Path == "/api/login" {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			received = string(b)
			receivedMethod = r.Method
			receivedContentType = r.Header.Get("Content-Type")
			receivedCount++
			receivedRequests = append(receivedRequests, receivedRequest{r.Method, r.Header.Get("Content-Type"), string(b)})
			mu.Unlock()
			select {
			case postReceived <- struct{}{}:
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("httptest unavailable: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: handler}}
	srv.Start()
	defer srv.Close()
	db, err := os.CreateTemp("", "raptor-integration-*.db")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	defer os.Remove(db.Name())
	store, err := NewRequestStore(db.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var results []*DiscoveredRequest
	var resultsMu sync.Mutex
	var saveErr error
	config := DefaultCrawlerConfig()
	config.SeedURL = srv.URL + "/login"
	config.MaxDepth = 0
	config.MaxPages = 1
	config.RequestTimeout = 15 * time.Second
	config.DBPath = db.Name()
	provider := sessionmgr.NewChromiumProvider(sessionmgr.ChromiumOptions{Headless: true})
	c, err := NewDynamicCrawler(config, func(r *DiscoveredRequest, e error) {
		if e == nil && r != nil {
			resultsMu.Lock()
			defer resultsMu.Unlock()
			results = append(results, r)
			if err := store.SaveRequest(r); err != nil && saveErr == nil {
				saveErr = err
			}
		}
	}, provider, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		if isChromeUnavailable(err) {
			t.Skipf("Chrome unavailable: %v", err)
		}
		t.Fatalf("crawler start failed: %v", err)
	}
	c.CrawlURL(ctx, config.SeedURL, 0)
	select {
	case <-postReceived:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for POST /api/login")
	}
	resultsMu.Lock()
	errSave := saveErr
	got := append([]*DiscoveredRequest(nil), results...)
	resultsMu.Unlock()
	for i, r := range got {
		t.Logf("callback[%d]: method=%s url=%s body_len=%d body=%q body_type=%s source_type=%s", i, r.Method, r.URL, len(r.Body), r.Body, r.BodyType, r.SourceType)
	}
	if errSave != nil {
		t.Fatalf("SaveRequest failed: %v", errSave)
	}
	mu.Lock()
	body := received
	method, contentType, count := receivedMethod, receivedContentType, receivedCount
	mu.Unlock()
	if method != "POST" || !strings.HasPrefix(contentType, "application/json") || count < 1 {
		t.Fatalf("received method=%s content-type=%s count=%d", method, contentType, count)
	}
	if body == "" {
		t.Fatal("test server did not receive POST /api/login")
	}
	if !strings.Contains(body, "email") || !strings.Contains(body, "password") {
		t.Fatalf("body=%s", body)
	}
	var payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("invalid received JSON: %v", err)
	}
	if payload.Email == "" || payload.Password == "" {
		t.Fatalf("empty payload: %#v", payload)
	}
	var found bool
	for _, r := range got {
		if r.Method == "POST" && strings.HasSuffix(r.URL, "/api/login") && r.Body != "" && strings.Contains(r.Body, payload.Email) && strings.Contains(r.Body, payload.Password) && r.BodyType != "" && r.SourceType != "" && r.SourceType != "dom_input" && r.SourceType != "anchor" && r.SourceType != "static_api_candidate" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no matching observed POST; results=%#v", got)
	}
	dbq, err := sql.Open("sqlite", db.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer dbq.Close()
	var methodDB, urlDB, bodyDB, bodyType, source string
	err = dbq.QueryRow(`SELECT method,url,body,body_type,source_type FROM discovered_requests WHERE UPPER(method)='POST' AND url LIKE '%/api/login%' LIMIT 1`).Scan(&methodDB, &urlDB, &bodyDB, &bodyType, &source)
	if err != nil {
		t.Fatalf("no persisted POST row: %v", err)
	}
	if !strings.Contains(bodyDB, payload.Email) || !strings.Contains(bodyDB, payload.Password) {
		t.Fatalf("persisted body missing payload: %s", bodyDB)
	}
	if count != 1 {
		t.Fatalf("duplicate form submissions: received %d", count)
	}
	if methodDB != "POST" || !strings.HasSuffix(urlDB, "/api/login") || bodyDB == "" || bodyType == "" || source == "dom_input" || source == "anchor" || source == "static_api_candidate" {
		t.Fatalf("invalid persisted row: %s %s %s %s %s", methodDB, urlDB, bodyDB, bodyType, source)
	}
	var check map[string]interface{}
	_ = json.Unmarshal([]byte(body), &check)
}

func TestDynamicCrawlerPersistsPUTPATCHDELETE(t *testing.T) {
	expected := map[string]string{
		"PUT":    `{"name":"test"}`,
		"PATCH":  `{"enabled":true}`,
		"DELETE": "",
	}
	var mu sync.Mutex
	received := map[string]string{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/work" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<form id="put-form"><input id="profile-name" name="name" required><button id="put-submit">Save</button></form>
<form id="patch-form"><input id="setting-name" name="setting" required><button data-testid="patch-submit">Update</button></form>
<form id="delete-form"><button id="delete-submit">Confirm</button></form>
<script>
document.querySelector('#put-form').addEventListener('submit',e=>{e.preventDefault();fetch('/api/profile',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:e.target.elements.name.value})})});
document.querySelector('#patch-form').addEventListener('submit',e=>{e.preventDefault();fetch('/api/settings',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:true})})});
document.querySelector('#delete-form').addEventListener('submit',e=>{e.preventDefault();fetch('/api/items/123',{method:'DELETE'})});
</script>`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		received[r.Method] = string(body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("httptest unavailable: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: handler}}
	srv.Start()
	defer srv.Close()
	dbFile, err := os.CreateTemp("", "raptor-methods-*.db")
	if err != nil {
		t.Fatal(err)
	}
	_ = dbFile.Close()
	defer os.Remove(dbFile.Name())
	store, err := NewRequestStore(dbFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	config := DefaultCrawlerConfig()
	config.SeedURL = srv.URL + "/work"
	config.MaxDepth, config.MaxPages = 0, 1
	config.RequestTimeout = 20 * time.Second
	crawler, err := NewDynamicCrawler(config, func(req *DiscoveredRequest, callbackErr error) {
		if callbackErr == nil && req != nil {
			if saveErr := store.SaveRequest(req); saveErr != nil {
				t.Errorf("save request: %v", saveErr)
			}
		}
	}, sessionmgr.NewChromiumProvider(sessionmgr.ChromiumOptions{Headless: true}), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer crawler.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := crawler.Start(ctx); err != nil {
		if isChromeUnavailable(err) {
			t.Skipf("Chrome unavailable: %v", err)
		}
		t.Fatal(err)
	}
	crawler.CrawlURL(ctx, config.SeedURL, 0)
	mu.Lock()
	gotReceived := maps.Clone(received)
	mu.Unlock()
	for method, body := range expected {
		if gotReceived[method] != body {
			t.Errorf("%s received body=%q, want %q", method, gotReceived[method], body)
		}
		var url, storedBody, bodyType, source, stack string
		err := store.db.QueryRow(`SELECT url,body,body_type,source_type,call_stack FROM discovered_requests WHERE method=?`, method).Scan(&url, &storedBody, &bodyType, &source, &stack)
		if err != nil {
			t.Errorf("%s missing persisted request: %v", method, err)
			continue
		}
		if storedBody != body || source == "runtime_trace" || !strings.HasPrefix(url, srv.URL+"/api/") {
			t.Errorf("%s invalid row url=%q body=%q body_type=%q source=%q", method, url, storedBody, bodyType, source)
		}
		if method != "DELETE" && (bodyType != "json" || stack == "") {
			t.Errorf("%s missing JSON type/runtime attribution: body_type=%q stack_len=%d", method, bodyType, len(stack))
		}
	}
}

func TestWorkflowStateIdentityChangesAcrossRerenders(t *testing.T) {
	first := []map[string]interface{}{{"type": "text", "name": "name", "id": "shared", "label": "Name", "required": true}}
	second := []map[string]interface{}{{"type": "email", "name": "email", "id": "shared", "label": "Email", "required": true}}
	if formWorkflowFingerprint("https://example.test/work", "dialog", "Step 1", first, "Next") ==
		formWorkflowFingerprint("https://example.test/work", "dialog", "Step 2", second, "Submit") {
		t.Fatal("wizard states that reuse a selector were deduplicated")
	}
	control := map[string]interface{}{"selector": "#shared", "semanticType": "tab", "label": "Details", "expanded": "false", "selected": "false"}
	a := controlWorkflowFingerprint("https://example.test/work", "dom-a", control, "")
	control["selected"] = "true"
	if a != controlWorkflowFingerprint("https://example.test/work", "dom-b", control, "") {
		t.Fatal("transient control state changed semantic identity")
	}
}

func TestSemanticControlIdentitySeparatesRecords(t *testing.T) {
	a := map[string]interface{}{"semanticType": "button", "label": "Like", "recordIdentity": "data-id=1"}
	b := map[string]interface{}{"semanticType": "button", "label": "Like", "recordIdentity": "data-id=2"}
	if controlWorkflowFingerprint("https://example.test/items", "", a, "") == controlWorkflowFingerprint("https://example.test/items", "", b, "") {
		t.Fatal("record controls collapsed")
	}
}

func TestSubmitActionNormalizationIgnoresLoadingText(t *testing.T) {
	if formWorkflowFingerprint("https://example.test/login", "", "", nil, "Sign In") != formWorkflowFingerprint("https://example.test/login", "", "", nil, "Signing in...") {
		t.Fatal("transient submit label changed identity")
	}
}

func TestSensitiveRedactionCoversEncodedAndJWTValues(t *testing.T) {
	text := `refreshToken=secret&password=hidden&x=ok eyJhbGciOiJIUzI1NiJ9.payload.signature`
	redacted := redactSensitiveText(text)
	if strings.Contains(redacted, "secret") || strings.Contains(redacted, "hidden") || strings.Contains(redacted, "eyJhbGci") {
		t.Fatalf("sensitive value leaked: %s", redacted)
	}
}

func TestOptionsRetainedButExcludedFromReplay(t *testing.T) {
	store, err := NewRequestStore(t.TempDir() + "/requests.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, method := range []string{"OPTIONS", "POST"} {
		req := &DiscoveredRequest{ID: "req-" + method, URL: "https://example.test/api/items", Method: method, SourceType: "cdp_observed", LifecycleState: "completed", CreatedAt: time.Now()}
		if err := store.SaveRequest(req); err != nil {
			t.Fatal(err)
		}
	}
	var internal int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM discovered_requests WHERE method='OPTIONS'`).Scan(&internal); err != nil || internal != 1 {
		t.Fatalf("OPTIONS telemetry count=%d err=%v", internal, err)
	}
	replay, err := requestReplayRows(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay) != 1 || replay[0].Method != "POST" {
		t.Fatalf("replay rows=%v", replay)
	}
}

func TestDynamicModalDrawerAndWizardFormsEnterQueueAndExecute(t *testing.T) {
	var mu sync.Mutex
	received := map[string]int{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<button id="modal-open">Open modal</button><button id="drawer-open">Open drawer</button>
<div id="host"></div><script>
const host=document.querySelector('#host');
document.querySelector('#modal-open').onclick=()=>{host.innerHTML='<dialog open id="wizard"><h2>Step 1</h2><form id="shared"><input name="name" required><button>Next</button></form></dialog>';document.querySelector('#shared').onsubmit=e=>{e.preventDefault();host.innerHTML='<dialog open id="wizard"><h2>Step 2</h2><form id="shared"><input name="email" type="email" required><button>Finish</button></form></dialog>';document.querySelector('#shared').onsubmit=x=>{x.preventDefault();fetch("/created",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:x.target.elements.email.value})})}}};
document.querySelector('#drawer-open').onclick=()=>{host.innerHTML='<div class="drawer open"><h2>Update</h2><form id="update"><input name="title" required><button>Save</button></form></div>';document.querySelector('#update').onsubmit=e=>{e.preventDefault();fetch("/updated",{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({title:e.target.elements.title.value})})}};
</script>`)
		case "/created", "/updated":
			mu.Lock()
			received[r.Method]++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			http.NotFound(w, r)
		}
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("httptest unavailable: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: handler}}
	srv.Start()
	defer srv.Close()
	config := DefaultCrawlerConfig()
	config.SeedURL, config.MaxPages, config.RequestTimeout = srv.URL, 1, 30*time.Second
	c, err := NewDynamicCrawler(config, func(*DiscoveredRequest, error) {}, sessionmgr.NewChromiumProvider(sessionmgr.ChromiumOptions{Headless: true}), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		if isChromeUnavailable(err) {
			t.Skipf("Chrome unavailable: %v", err)
		}
		t.Fatal(err)
	}
	c.CrawlURL(ctx, config.SeedURL, 0)
	mu.Lock()
	post, patch := received["POST"], received["PATCH"]
	mu.Unlock()
	if post != 1 || patch != 1 {
		t.Fatalf("dynamic workflows did not execute exactly once: POST=%d PATCH=%d", post, patch)
	}
}

func crawlDelayedRouteFixture(t *testing.T, delay time.Duration, marker string) []string {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path != "/" {
			_, _ = io.WriteString(w, `<main>`+r.URL.Path+`</main>`)
			return
		}
		_, _ = io.WriteString(w, `<main id="__next"></main><script>
setTimeout(()=>{document.querySelector('#__next').innerHTML='<a href="/Login">Login</a><a href="/forgot-password">Forgot password</a>'}, `+
			time.Duration(delay).String()[0:len(time.Duration(delay).String())-2]+`)
</script><script data-next-page="`+marker+`"></script>`)
	})
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("httptest unavailable: %v", err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: handler}}
	srv.Start()
	defer srv.Close()

	config := DefaultCrawlerConfig()
	config.SeedURL, config.MaxDepth, config.MaxPages = srv.URL, 2, 3
	config.RequestTimeout = 10 * time.Second
	c, err := NewDynamicCrawler(config, func(*DiscoveredRequest, error) {}, sessionmgr.NewChromiumProvider(sessionmgr.ChromiumOptions{Headless: true}), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		if isChromeUnavailable(err) {
			t.Skipf("Chrome unavailable: %v", err)
		}
		t.Fatal(err)
	}
	return c.CrawlURL(ctx, srv.URL, 0)
}

func assertLoginRoutes(t *testing.T, routes []string) {
	t.Helper()
	found := map[string]bool{}
	for _, route := range routes {
		if u, err := neturl.Parse(route); err == nil {
			found[u.Path] = true
		}
	}
	if !found["/Login"] || !found["/forgot-password"] {
		t.Fatalf("delayed rendered routes not discovered: %v", routes)
	}
}

func TestClientRenderedLinksDiscoveredAfterSettling(t *testing.T) {
	assertLoginRoutes(t, crawlDelayedRouteFixture(t, 300*time.Millisecond, "client-rendered"))
}

func TestNextJSDelayedHydrationDiscoversRoutes(t *testing.T) {
	assertLoginRoutes(t, crawlDelayedRouteFixture(t, 350*time.Millisecond, "/_next/static/chunks/app.js"))
}

func TestLinksWithoutFormsOrControlsStillQueueAfterWorkflowScheduler(t *testing.T) {
	var emitted int
	c := &DynamicCrawler{
		config:           CrawlerConfig{StayInDomain: true},
		allowedHost:      "example.test",
		maxDepth:         2,
		seenURLs:         map[string]struct{}{},
		seenFingerprints: map[string]struct{}{},
		callback: func(req *DiscoveredRequest, err error) {
			if err == nil && req != nil && req.SourceType == "anchor" {
				emitted++
			}
		},
	}
	var snap domSnapshot
	snap.Links = append(snap.Links,
		struct {
			Href string `json:"href"`
		}{Href: "https://example.test/Login"},
		struct {
			Href string `json:"href"`
		}{Href: "https://example.test/forgot-password"},
	)
	var next []string
	c.processSnapshotLinks(snap, "https://example.test/", 0, map[string]struct{}{}, &next)
	if emitted != 2 || len(next) != 2 {
		t.Fatalf("anchor processing after scheduler introduction: emitted=%d next=%v", emitted, next)
	}
}

func newRouteTestCrawler() *DynamicCrawler {
	return &DynamicCrawler{
		config: CrawlerConfig{StayInDomain: true}, allowedHost: "example.test",
		maxDepth: 2, seenURLs: map[string]struct{}{}, seenFingerprints: map[string]struct{}{},
		callback: func(*DiscoveredRequest, error) {},
	}
}

func TestServerRenderedAnchorQueuesDocumentRoute(t *testing.T) {
	c := newRouteTestCrawler()
	var snap domSnapshot
	snap.Links = append(snap.Links, struct {
		Href string `json:"href"`
	}{Href: "https://example.test/login"})
	var next []string
	c.extractRouteCandidates(snap, nil, "https://example.test/", 0, map[string]struct{}{}, &next)
	if len(next) != 1 || next[0] != "https://example.test/login" {
		t.Fatalf("server-rendered anchor was not queued: %v", next)
	}
}

func TestDelayedRSCPrefetchQueuesCleanDocumentRoute(t *testing.T) {
	c := newRouteTestCrawler()
	var next []string
	c.extractRouteCandidates(domSnapshot{}, []runtimeRequestTrace{
		{Method: "GET", URL: "https://example.test/login?campaign=trial&_rsc=test"},
	}, "https://example.test/", 0, map[string]struct{}{}, &next)
	if len(next) != 1 || next[0] != "https://example.test/login?campaign=trial" {
		t.Fatalf("RSC route was not cleaned while preserving application query: %v", next)
	}
}

func TestFreshWorkflowSnapshotExposesNewAnchorToRouteCollector(t *testing.T) {
	c := newRouteTestCrawler()
	seen := map[string]struct{}{}
	var next []string
	c.extractRouteCandidates(domSnapshot{}, nil, "https://example.test/", 0, seen, &next)
	var fresh domSnapshot
	fresh.Links = append(fresh.Links, struct {
		Href string `json:"href"`
	}{Href: "https://example.test/revealed"})
	c.extractRouteCandidates(fresh, nil, "https://example.test/", 0, seen, &next)
	if len(next) != 1 || next[0] != "https://example.test/revealed" {
		t.Fatalf("fresh workflow snapshot route was not queued: %v", next)
	}
}
